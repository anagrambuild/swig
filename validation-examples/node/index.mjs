import { ed25519 } from "@noble/curves/ed25519";
import {PublicKey} from "@solana/web3.js";

function ANBFSignInMessage(
  domain,
  address,
  statement,
  uri,
  version,
  chainId,
  nonce,
  issuedAt,
  expirationTime
) {
  let message = `${domain} wants you to sign in with your Solana account:\n${address}`;
  if (statement) {
    message += `\n${statement}\n`;
  }
  if (uri) {
    message += `URI: ${uri}\n`;
  }
  if (version) {
    message += `Version: ${version}\n`;
  }
  if (chainId) {
    message += `Chain ID: ${chainId}\n`;
  }
  if (nonce) {
    message += `Nonce: ${nonce}\n`;
  }
  if (issuedAt) {
    message += `Issued At: ${issuedAt}\n`;
  }
  if (expirationTime) {
    message += `Expiration Time: ${expirationTime}`;
  }
  return message;
}

async function encode(header, payload) {
    let payload = JSON.parse(JSON.stringify(payload)); // deep copy
    delete payload.rawMessage;
    delete payload.account;
    const header = Buffer.from(JSON.stringify(header));
    const payload = Buffer.from(JSON.stringify(payload));
    const data = Buffer.concat([header, payload]);
    this.encoded = new Uint8Array(data);
}


function main() {
  console.log('Take a swig!')
  const args = process.argv.slice(2)
  const jwt = args[0]
  if (!jwt) {
    console.error('No JWT provided')
    return
  }
  const parts = jwt.split('.')
  if (parts.length !== 3) {
    console.error('Invalid JWT')
    return
  }
  const header = JSON.parse(Buffer.from(parts[0], 'base64').toString())
  const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString())
  const signature = Buffer.from(parts[2], 'base64')
  if (!"rawMessage" in payload) {
    console.error('Invalid JWT')
    return
  }
  const aud = "your expected audience"
  const rawMessage = payload.rawMessage
  const message = ANBFSignInMessage(
    this.payload.aud,
    this.payload.iss,
    null,
    null,
    "1",
    null,
    encode(this.header, this.payload),
    issuedAt,
    expirationTime
  );
  if (rawMessage !== message) {
    console.error('Invalid JWT')
    return
  }
  if (payload.exp < Date.now() / 1000) {
    console.error('JWT expired')
    return
  }
  if (payload.aud !== aud) {
    console.error('Invalid JWT')
    return
  }
  const publicKey = new PublicKey(payload.iss)
  const sigverify = ed25519.verify(signature, Buffer.from(rawMessage), publicKey.toBytes())
  if (!sigverify) {
    console.error('Invalid JWT')
    return
  }
  
  console.log('JWT is valid')
}