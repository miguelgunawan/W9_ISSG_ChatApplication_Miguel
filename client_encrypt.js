const io = require("socket.io-client");
const readline = require("readline");
const crypto = require("crypto"); // pakai modul crypto untuk generate key rsa

const socket = io("http://localhost:3000");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  prompt: "> ",
});

let targetUsername = "";
let username = "";
const users = new Map();
let privateKey = "";
let publicKey = "";

// Meng generate pasangan key RSA
function generateKeyPair() { 
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 2048, 
    publicKeyEncoding: { type: "spki", format: "pem" }, 
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return { publicKey, privateKey };
}

function encryptMessage(message, targetPublicKey) {
  return crypto.publicEncrypt(targetPublicKey, Buffer.from(message)).toString("base64");
  // encrypt pesan (public key)
}

function decryptMessage(ciphertext) {
  try {
    return crypto.privateDecrypt(privateKey, Buffer.from(ciphertext, "base64")).toString();
  } catch (err) {
    return "Failed to decrypt message.";
  }
   // Pesan  di decrypt (private key)
}

({ publicKey, privateKey } = generateKeyPair()); //generate private key dan public key

socket.on("connect", () => {
  console.log("Connected to the server");

  socket.on("init", (keys) => {
    keys.forEach(([user, key]) => users.set(user, key));
    console.log(`\nThere are currently ${users.size} users in the chat`);
    rl.prompt();

    rl.question("Enter your username: ", (input) => {
      username = input;
      console.log(`Welcome, ${username} to the chat`);

      socket.emit("registerPublicKey", {
        username,
        publicKey,
      });

      rl.prompt();

      rl.on("line", (message) => {
        if (message.trim()) {
          if ((match = message.match(/^!secret (\w+)$/))) {
            targetUsername = match[1];
            console.log(`Now secretly chatting with ${targetUsername}`);
          } else if (message.match(/^!exit$/)) {
            console.log(`No more secretly chatting with ${targetUsername}`);
            targetUsername = "";
          } else {
            let encryptedMessage = message;
            if (targetUsername) {
              // mengambil public key dari target user
              const targetPublicKey = users.get(targetUsername); 
              if (targetPublicKey) {
                // pesan kemudian di encrypt menggunakan public key target  
                encryptedMessage = encryptMessage(message, targetPublicKey); 
              } else {
                console.log(`Public key for ${targetUsername} not found.`);
              }
            }
            socket.emit("message", { username, message: encryptedMessage, targetUsername }); 
          }
        }
        rl.prompt();
      });
    });
  });
});

socket.on("newUser", (data) => {
  const { username, publicKey } = data;
  users.set(username, publicKey);
  console.log(`${username} joined the chat`);
  rl.prompt();
});

socket.on("message", (data) => {
  const { username: senderUsername, message: senderMessage, targetUsername } = data;

  if (username === senderUsername && targetUsername) {
    return;
  }

  if (targetUsername && targetUsername !== username) { 
    console.log(`${senderUsername}: ${senderMessage}`); // menampilkan ciphertext
  } else {
    let outputMessage;
    if (targetUsername === username) { // cek apakah username sesuai atau tidak dengan target user nya
      outputMessage = decryptMessage(senderMessage); // pesan kemudian di decrypt (berupa tampilan pesan)
    } else { 
      outputMessage = senderMessage;
    }

    console.log(`${senderUsername}: ${outputMessage}`);
  }

  rl.prompt();
});



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