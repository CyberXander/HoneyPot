"use strict";

const EventEmitter = require('events');
const { spawn } = require('child_process');
const chalk = require('chalk');
const nodemailer = require('nodemailer');
let banip=[];
class IcmpEchoLogger extends EventEmitter {
  constructor() {
    super();
    this.start();
    this.lastPingReceivedTime = Date.now();
	this.ipAddress=undefined;
    this.alertSent = false;
    this.pingCounter = 0;
    
    //this.checkDiscontinuity();
    this.checkDoSAttack();
  }

  start() {
    let cmd = 'tcpdump';
    let args = ['-nvvv', '-l', '-i', 'wlan0', 'icmp', 'and', 'icmp[icmptype]=icmp-echo'];
    this.tcpdumpProcess = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'ignore'] });
    this.tcpdumpProcess.on('error', (err) => {
      console.log(chalk.bgYellow.bold('Warning:') + ' Cannot spawn tcpdump. Error code: ' + err.code);
    });
    this.tcpdumpProcess.stdout.on('data', (data) => {
      this.lastPingReceivedTime = Date.now();
      this.pingCounter++;

      let echo_request = data.toString();
      let lines = echo_request.split("\n");
      if (lines[1] === undefined) return;
      let ip_address = lines[1].split(">")[0];
      if (ip_address === undefined || ip_address.length === 0) return;
      else ip_address = ip_address.trim();
	  this.ipAddress=ip_address;

      this.emit('data', {
        'ip': ip_address,
        'service': 'ping',
        'request': 'ICMP echo request from ' + ip_address,
        'request_headers': echo_request
      });
    });
  }

  checkDiscontinuity() {
    setInterval(() => {
      const currentTime = Date.now();
      const discontinuityThreshold = 5000; // set to 5 seconds for example
      if ((currentTime - this.lastPingReceivedTime) > discontinuityThreshold || this.pingCounter === 0) {
        this.pingCounter = 0;
        if(!banip.includes(this.ipAddress)){
          spawn("iptables" ,['-A', 'INPUT' ,'-s' ,this.ipAddress, '-p' ,'icmp' ,'-j' ,'DROP']);
          banip.push(this.ipAddress);
          this.sendEmailAlert(this.ipAddress, 'Date.now()' , 'banned');
        }
        if (!this.alertSent) {
        
          this.alertSent = true;
          let msg='icmp';
          //this.sendEmailAlert(this.ipAddress, this.lastPingReceivedTime,msg);
          
        }
      } else {
        this.alertSent = false;
      }
    }, 1000);
  }

  checkDoSAttack() {
    const requestThreshold = 10; // number of requests within time frame to trigger DoS alert
    const timeFrame = 5000; // time frame for counting requests in milliseconds
    const requestCounts = {}; // dictionary to store request counts for each IP address

    setInterval(() => {
      const currentTime = Date.now();
      Object.keys(requestCounts).forEach(ipAddress => {
        if ((currentTime - requestCounts[ipAddress].lastRequestTime) > timeFrame) {
          delete requestCounts[ipAddress];
        }
      });
    }, timeFrame);

    setInterval(() => {
      Object.keys(requestCounts).forEach(ipAddress => {
        if (requestCounts[ipAddress].count >= requestThreshold ) {
          if(!banip.includes(ipAddress)){
            spawn("iptables" ,['-A', 'INPUT' ,'-s' ,ipAddress, '-p' ,'icmp' ,'-j' ,'DROP']);
            banip.push(ipAddress);
            console.log(banip);
            //console.log(Object.keys(requestCounts));
          
          if(!this.alertSent){
          this.alertSent = true;
          let msg ='Dos Attack';
          this.sendEmailAlert(ipAddress, requestCounts[ipAddress].lastRequestTime, 'DoS Attack');
          }
        }
          
        }
        else this.alertSent=false;
      });
    }, 1000);

    this.on('data', data => {
      const ipAddress = data.ip;
      if (!requestCounts[ipAddress]) {
        requestCounts[ipAddress] = {
          count: 1,
          lastRequestTime: Date.now()
        };
      } else {
        requestCounts[ipAddress].count++;
        requestCounts[ipAddress].lastRequestTime = Date.now();
      }
    });
  }

  sendEmailAlert(ipAddress, timestamp,msg) {
    let txt=null;
    let sub=null;
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'testemailfinalyr@gmail.com',
        pass: 'yrkauacgzaugjnaz'
      }
    });
if (msg=='DoS Attack'){
  txt = ' ICMP Flood detected from "'+ ipAddress +'" received at '+ new Date(timestamp).toString()+'.\nYour device was under DOS Attack.\nThus ICMP traffic from '+ ipAddress + ' is BANNED.';
  sub = 'ICMP FLOOD alert';
}
  else if (msg=='icmp'){
    txt = 'ICMP echo request detected from "'+ ipAddress +'" received at '+ new Date(timestamp).toString()+'.\n Your device was under ping scan.';
    sub = 'PING SCAN ';
}
else if (msg == 'banned'){
  txt = ipAddress + 'banned';
  sub= 'BANNED';
}
else console.log("invalid");

const mailOptions = {
  from: 'testemailfinalyr@gmail.com',
  to: 'mayank1rn19ec073@gmail.com',
  subject: sub,
  text: txt
  
};

    transporter.sendMail(mailOptions, function (error, info) {
      if (error) {
        console.log('Error sending email: ', error);
      } else {
        console.log(chalk.bgYellow('Email sent :')  + info.response);
      }
    });
  }
}


module.exports = IcmpEchoLogger;
