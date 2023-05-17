'use strict';

const EventEmitter = require('events');
const { spawn } = require('child_process');
const chalk = require('chalk');
const nodemailer = require('nodemailer');

class SynFloodLogger extends EventEmitter {
  constructor() {
    super();
    this.start();
    this.lastPacketReceivedTime = Date.now();
    this.alertSent = false;
    this.packetCounter = 0;
    //this.checkDiscontinuity();
    this.checkDoSAttack();
}

  start() {
    let cmd = 'tcpdump';
    let args = ['-nvvv', '-l', '-i', 'wlan0', '"tcp[tcpflags] & (tcp-syn) != 0 "','|' ,'awk' ,'{print $3}' ,'|' ,'sort' ,'|' ,'uniq' ,'-c' ,'|' ,'sort'];
    this.tcpdumpProcess = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'ignore'] });
    this.tcpdumpProcess.on('error', (err) => {
      console.log(chalk.bgYellow.bold('Warning:') + ' Cannot spawn tcpdump. Error code: ' + err.code);
    });
    this.tcpdumpProcess.stdout.on('data', (data) => {
      this.lastPacketReceivedTime = Date.now();
      this.packetCounter++;

      let syn_packet = data.toString();
      let lines = syn_packet.split("\n");
      if (lines[1] === undefined) return;
      let ip_address = lines[1].split(">")[0];
      if (ip_address === undefined || ip_address.length === 0) return;
      else ip_address = ip_address.trim();
      this.ipAddress=ip_address;
      this.emit('data', {
        'ip': ip_address,
        'service': 'SYN',
        'request': 'SYN packet received from ' + ip_address,
        'request_headers': syn_packet
      });
    });
  }

  // checkDiscontinuity() {
  //   setInterval(() => {
  //     const currentTime = Date.now();
  //     const discontinuityThreshold = 5000; // set to 5 seconds for example
  //     if ((currentTime - this.lastPacketReceivedTime) > discontinuityThreshold || this.packetCounter === 0) {
  //       this.packetCounter = 0;
  //       if (!this.alertSent) {
  //         this.alertSent = true;
  //         this.sendEmailAlert(this.ipAddress,this.lastPacketReceivedTime);
  //       }
  //     } else {
  //       this.alertSent = false;
  //     }
  //   }, 1000);
 // }
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
          // if(!banip.includes(ipAddress)){
          //   spawn("iptables" ,['-A', 'INPUT' ,'-s' ,ipAddress, '-p' ,'icmp' ,'-j' ,'DROP']);
          //   banip.push(ipAddress);
          //   console.log(banip);
          //   //console.log(Object.keys(requestCounts));
          
          if(!this.alertSent){
          this.alertSent = true;
          let msg ='Dos Attack';
          this.sendEmailAlert(ipAddress, requestCounts[ipAddress].lastRequestTime, 'DoS Attack');
          }
        //}
          
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


  sendEmailAlert(ipAddress,timestamp) {
    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: 'testemailfinalyr@gmail.com',
        pass: 'yrkauacgzaugjnaz'
      }
    });

    const mailOptions = {
      from: 'testemailfinalyr@gmail.com',
      to: 'mayank1rn19ec073@gmail.com',
      subject: 'SYN Flood Alert',
      text: 'SYN flood detected from "'+ ipAddress +'" received at '+ new Date(timestamp).toString()+'.'
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
  module.exports = SynFloodLogger;