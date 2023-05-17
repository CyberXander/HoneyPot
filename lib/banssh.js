"use strict";

const config = require('./../config');
const helper = require('./../lib/helper');
const EventEmitter = require('events');
const fs = require('fs');
const net = require('net');
const FtpSrv = require('ftp-srv');
const ssh2 = require('ssh2');
const chalk = require('chalk');

class SocketServer extends EventEmitter {
	/**
	 * @param {number} port - Socket's Port Number
	 * @param {string} name - Service Name
	 */
	constructor(port, name) {
		super();
		this.port = port;
		this.name = name;
		this.start();
	}

	start() {
		throw new Error('You have to implement the `start` method!');
	}

	onError(err) {
		if (err.code === 'EADDRINUSE') console.log(chalk.bgYellow.bold('Warning:') + ' Cannot start `' + this.name + '` service on port ' + this.port + '. Error Code: EADDRINUSE, Address already in use.');
		else if (err.code === 'EACCES') console.log(chalk.bgYellow.bold('Warning:') + ' Cannot start `' + this.name + '` service on port ' + this.port + '. Error Code: EACCES, Permission Denied.');
		else throw new Error(err);
	}
}

class SshSocketServer extends SocketServer {
	constructor(port, name, maxFailedAttempts, banTime) {
		super(port, name);
		this.maxFailedAttempts = maxFailedAttempts;
		this.banTime = banTime;
		this.failedAttempts = new Map();
		this.bannedIps = new Set();
	}

	start() {
		new ssh2.Server({
			hostKeys: [fs.readFileSync(__dirname + '/../etc/ssh2.private.key')],
			banner: 'Hi there!',
			ident: 'OpenSSH_7.6'
		}, (client) => {
			client.on('authentication', (ctx) => {
				if (ctx.method !== 'password') return ctx.reject(['password']);
				else if (ctx.method === 'password') {
					const ip = client._client_info.ip;
					if (this.bannedIps.has(ip)) {
						// IP is banned, reject the authentication attempt
						this.emit('banned', {
							'ip': ip,
							'service': this.name,
							'request': 'Authentication attempt from banned IP: ' + ip,
							'request_headers': helper.formatHeaders(client._client_info.header)
						});
						ctx.reject(['password']);
						client.end();
						return;
					}
					const username = ctx.username;
					const password = ctx.password;
					if (this.failedAttempts.has(ip)) {
						// IP has previous failed attempts, increment the count
						const count = this.failedAttempts.get(ip) + 1;
						this.failedAttempts.set(ip, count);
						if (count >= this.maxFailedAttempts) {
							// IP has exceeded the maximum failed attempts, ban the IP
							this.bannedIps.add(ip);
							this.failedAttempts.delete(ip);
							this.emit('banned', {
								'ip': ip,
								'service': this.name,
								'request': 'IP banned due to too many failed authentication attempts: ' + ip,
								'request_headers': helper.formatHeaders(client._client_info.header)
							});
							setTimeout(() => {
								this.bannedIps.delete(ip);
							}, this.banTime);
						} else {
							// IP has not yet exceeded the maximum failed attempts, emit the failed attempt event
							this.emit('failed', {
                                'ip': ip,
                                'service': this.name,
                                'request': 'Authentication attempt failed for user "' + username + '" from IP ' + ip,
                                'request_headers': helper.formatHeaders(client._client_info.header)
                                });
                                ctx.reject(['password']);
                                }
                                }
                                }).on('ready', () => {
                                client.on('session', (accept, reject) => {
                                const session = accept();
                                session.once('exec', (accept, reject, info) => {
                                const stream = accept();
                                stream.on('data', (data) => {
                                stream.write('You wrote: ' + data);
                                });
                                stream.stderr.write('Oh no, an error occurred!\n');
                                stream.stderr.end();
                                stream.end('Thanks for using ' + this.name + '!\n');
                                });
                                });
                                }).on('end', () => {
                                console.log('Client disconnected');
                                }).on('error', (err) => {
                                console.log('Error occurred:', err);
                                });
                                }).listen(this.port, () => {
                                console.log(chalk.green('SSH Server started on port ' + this.port));
                                }).on('error', (err) => {
                                    this.onError(err);
                                    });
                                    }
                                    }
    const CustomSocketServer = (port, name) => {
        if (name === 'ssh') {
            return new SshSocketServer(port, name);
        }
        // else if (name === 'ftp') {
        //     return new FtpSocketServer(port, name);
        // }
        // else {
        //     return new GenericSocketServer(port, name);
        // }
    };
    
    module.exports = CustomSocketServer;