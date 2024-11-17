const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto"); // untuk generate kunci RSA

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let registeredUsername = "";
let username = "";
const users = new Map();

// Generate  kunci RSA dengan 2048 bit agar aman
const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

socket.on("connect", () => {
  console.log("Connected to the server");

  // menerima users dari "init" server
  socket.on("init", (keys) => {
    keys.forEach(([user, key]) => users.set(user, key));
    console.log(`There are currently ${users.size} users in the chat`);

    rl.question("Enter your username: ", (input) => {
      username = input;
      registeredUsername = input;
      console.log(`Welcome, ${username} to the chat`);

      // meregist public key dari user ke server
      socket.emit("registerPublicKey", {
        username,
        publicKey: publicKey.export({ type: "pkcs1", format: "pem" }),
      });
      rl.prompt();

      rl.on("line", (message) => {
        if (message.trim()) {
          if ((match = message.match(/^!impersonate (\w+)$/))) {
            username = match[1];
            console.log(`Now impersonating as ${username}`);
          } else if (message.match(/^!exit$/)) {
            username = registeredUsername;
            console.log(`Now you are ${username}`);
          } else {

            // Membuat Signature untuk message sebelum dikirim
            const sign = crypto.createSign("sha256");
            sign.update(message); 
            sign.end();
            const signature = sign.sign(privateKey, "hex"); //convert  hasil signature ke format hexadecimal

            socket.emit("message", {
              username,
              message,
              signature, 
            });
          }
        }
        rl.prompt();
      });
    });
  });
});

// Menampung user yang baru join agar mendapat public key
socket.on("newUser", (data) => {
  const { username, publicKey } = data;
  users.set(username, publicKey);
  console.log(`${username} joined the chat`);
  rl.prompt();
});

// Menerima pesan dan verify signature
socket.on("message", (data) => {
    const { username: senderUsername, message: senderMessage, signature } = data;
  
    // checkusername yang mengirim pesan sama dengan username yang asli 
    if (senderUsername !== username) {
      const senderPublicKey = users.get(senderUsername);
  
      if (senderPublicKey && signature) {
        const verify = crypto.createVerify("sha256"); // membuat verifikasi dengan sha256
        verify.update(senderMessage);
        verify.end();
  
        // melakukan proses verifikasi signature dengan kunci publik pengirim
        const isVerified = verify.verify(senderPublicKey, signature, "hex");
  
        if (isVerified) {
          console.log(`${senderUsername}: ${senderMessage}`); // jika benar maka pesan akan terkirim 
        } else {
          console.log(`${senderUsername}: ${senderMessage}`); // jika salah maka akan muncul warning di dalam chat nya
          console.log(`Warning: This user is fake`);
        }
      } else if (!signature) {
        // cek signature sudah dibuat atau belum
        console.log(`Warning: ${senderUsername} sent a message without a signature`);
      } else {
        // cek public key nya sudah ada atau tidak
        console.log(`Warning: No public key found for ${senderUsername}`);
      }
    }
  
    rl.prompt();
  });
  

// Disconnect
socket.on("disconnect", () => {
  console.log("Server disconnected, Exiting...");
  rl.close();
  process.exit(0);
});

rl.on("SIGINT", () => {
  console.log("\nExiting...");
  socket.disconnect();
  rl.close();
  process.exit(0);
});