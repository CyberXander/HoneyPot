const { exec } = require('child_process');

exec('/home/cyberx/Desktop/Honeypot/tcpdump-script.sh', (err, stdout, stderr) => {
  if (err) {
    console.error(`Error running tcpdump: ${err}`);
    return;
  }
  
  const lines = stdout.split('\n');
  for (const line of lines) {
    const parts = line.trim().split(/\s+/);
    if (parts.length === 2 && parseInt(parts[0]) > 100) {
      console.log(`Possible ping flood from ${parts[1]}`);
    }
  }
});
