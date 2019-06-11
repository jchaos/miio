'use strict';

const crypto = require('crypto');
const debug = require('debug')('miio:packet');

class Packet {
	constructor(discovery = false) {
		this.discovery = discovery;

		// 一个数字+1是一个字节
		this.header = Buffer.alloc(4 + 4 + 4 + 4 + 16);

		//(32(hello + length) + 32(unknown1) + 32(device id) + 32(stamp) + 128(checksum))

		// 固定起始2131 1个16进制=4位 2个16进制=8位 8位=1字节 
		this.header[0] = 0x21;
		this.header[1] = 0x31;

		// 从Unknown1至末尾全部填充FF
		for(let i=4; i<32; i++) {
			this.header[i] = 0xff;
		}

		// 初始化时间戳
		this._serverStampTime = 0;

		// 初始化token
		this._token = null;
	}

	handshake() {
		this.data = null;
	}

	handleHandshakeReply() {
		if(this._token === null) {
			const token = this.checksum;
			if(token.toString('hex').match(/^[fF0]+$/)) {
				// Device did not return its token so we set our token to null
				this._token = null;
			} else {
				this.token = this.checksum;
			}
		}
	}

	// 查看是否需要握手
	get needsHandshake() {
		/*
		 * Handshake if we: 下面情况握手
		 * 1) do not have a token 没有token
		 * 2) it has been longer then 120 seconds since last received message 距上次获取消息超过120秒
		 */
		return ! this._token || (Date.now() - this._serverStampTime) > 120000;
	}

	// 得到buffer
	get raw() {
		// 如果存在data则返回raw数据 data就是json命令字符串
		if(this.data) {
			// Send a command to the device
			// 向设备发送命令
			// 发送命令token是必须的
			if(! this._token) {
				throw new Error('Token is required to send commands');
			}

			// 设置Unknown1总是0x00除了握手时0xffffffff
			for(let i=4; i<8; i++) {
				this.header[i] = 0x00;
			}

			// Update the stamp to match server
			// 更新时间戳来匹配服务器
			if(this._serverStampTime) {
				// 微秒转秒初始化时这个值是0
				const secondsPassed = Math.floor(Date.now() - this._serverStampTime) / 1000;
				//保存 秒数
				this.header.writeUInt32BE(this._serverStamp + secondsPassed, 12);
			}

			// Encrypt the data
			// 数据加密 就是Payload 命令载体
			let cipher = crypto.createCipheriv('aes-128-cbc', this._tokenKey, this._tokenIV);
			let encrypted = Buffer.concat([
				cipher.update(this.data),
				cipher.final()
			]);

			// Set the length
			// 设置消息全部字节长度就是header里面前4个字节中第3和第4字节
			this.header.writeUInt16BE(32 + encrypted.length, 2);

			// Calculate the checksum
			// 计算checksum = [meta + unkown（00000000）+ 设备ID + stamp] + token + 加密后的载荷
			let digest = crypto.createHash('md5')
				.update(this.header.slice(0, 16))
				.update(this._token)
				.update(encrypted)
				.digest();

			// 把车个加密数据buffer拷贝到this.header16位起 也就是用这个数据替换token位置
			digest.copy(this.header, 16);

			debug('->', this.header);

			// 把这个header和payload结合起来
			return Buffer.concat([ this.header, encrypted ]);
		} else {
			// 没有命令数据就是握手
			// 握手时则头部声明长度设置成32
			this.header.writeUInt16BE(32, 2);

			// 从unknown1起全部设置为0xff
			for(let i=4; i<32; i++) {
				this.header[i] = 0xff;
			}

			//0x21310020 ffffffff ffffffff ffffffff

			debug('->', this.header);
			return this.header;
		}
	}

	// 设置
	set raw(msg) {
		// 拷贝32字节到header  等于用buffer直接覆盖 是设备返回的信息
		msg.copy(this.header, 0, 0, 32);
		debug('<-', this.header);

		// 直接解析header中的stamp
		const stamp = this.stamp;
		if(stamp > 0) {
			// If the device returned a stamp, store it
			// 如果设备返回了一个时间戳则保存服务器的时间戳(秒) 同时保存当前的时间(微秒)
			this._serverStamp = this.stamp;
			this._serverStampTime = Date.now();
		}

		// AES-128加密的命令数据 payload
		const encrypted = msg.slice(32);

		if(this.discovery) {
			// 这个包只能用来发现设备
			// This packet is only intended to be used for discovery
			this.data = encrypted.length > 0;
		} else {
			// Normal packet, decrypt data
			// 普通发送包 加密数据
			// 存在AES-128密匙
			if(encrypted.length > 0) {
				// 检查是否存在token 没token无法解密
				if(! this._token) {
					debug('<- No token set, unable to handle packet');
					this.data = null;
					return;
				}

				// 计算checksum
				const digest = crypto.createHash('md5')
					.update(this.header.slice(0, 16))
					.update(this._token)
					.update(encrypted)
					.digest();

				const checksum = this.checksum;

				// checksum不对
				if(! checksum.equals(digest)) {
					debug('<- Invalid packet, checksum was', checksum, 'should be', digest);
					this.data = null;
				} else {
					//解密
					let decipher = crypto.createDecipheriv('aes-128-cbc', this._tokenKey, this._tokenIV);
					this.data = Buffer.concat([
						decipher.update(encrypted),
						decipher.final()
					]);
				}
			} else {
				//不存在AES-128密匙
				this.data = null;
			}
		}
	}

	get token() {
		// 返回token
		return this._token;
	}

	set token(t) {
		// 用一个字符串t生成token/key/IV
		this._token = Buffer.from(t);
		this._tokenKey = crypto.createHash('md5').update(t).digest();
		// 加密向量 MD5(MD5(Token)+Token) 
		this._tokenIV = crypto.createHash('md5').update(this._tokenKey).update(t).digest();
	}

	get checksum() {
		// 返回第16位之后的
		return this.header.slice(16);
	}

	get deviceId() {
		// 1位无符号32位整数 偏移8字节
		return this.header.readUInt32BE(8);
	}

	get stamp() {
		// 1位无符号32位整数 偏移12字节
		return this.header.readUInt32BE(12);
	}
}

module.exports = Packet;
