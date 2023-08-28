import {
  Adapter,
  MessageSignerWalletAdapter,
  SignInMessageSignerWalletAdapter,
} from "@solana/wallet-adapter-base";
import { PublicKey, Keypair } from "@solana/web3.js";
import { Buffer } from "buffer";
import * as crypto from "crypto";
import { ed25519 } from "@noble/curves/ed25519";

function checkURL(url: string): boolean {
  try {
    new URL(url);
    return true;
  } catch (_) {
    return false;
  }
}

function ANBFSignInMessage(
  domain: string,
  address: string,
  statement: string | null,
  uri: string | null,
  version: string | null,
  chainId: string | null,
  nonce: string | null,
  issuedAt: string | null,
  expirationTime: string | null
): string {
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

class KeyJWT {
  public header: {
    alg: string;
    typ: string;
  };
  public payload: {
    iss: string;
    sub: string;
    aud: string;
    exp: number;
    iat: number;
    [key: string]: any;
  };
  private encoded?: Uint8Array;
  private signature: string = "";
  private signed: boolean = false;

  constructor(
    audience: string,
    pubkey: PublicKey,
    expiry: number,
    payload: { [key: string]: any }
  ) {
    let now = Math.floor(Date.now() / 1000);
    this.header = {
      alg: "ES256K",
      typ: "JWT",
    };
    delete payload["exp"];
    delete payload["iat"];
    delete payload["iss"];
    delete payload["sub"];
    delete payload["aud"];
    //validate audience is a uri
    if (!checkURL(audience)) {
      throw new Error("Invalid audience");
    }

    this.payload = {
      iss: pubkey.toBase58(),
      sub: pubkey.toBase58(),
      aud: audience,
      iat: now,
      exp: now + expiry,
      ...payload,
    };
  }

  public async encode(): Promise<Uint8Array> {
    if (!this.encoded) {
      const header = Buffer.from(JSON.stringify(this.header));
      const payload = Buffer.from(JSON.stringify(this.payload));
      const data = Buffer.concat([header, payload]);
      this.encoded = new Uint8Array(data);
    }
    return this.encoded;
  }

  public async signWithKeypair(keypair: Keypair) {
    const data = await this.encode();
    const signature = ed25519.sign(data, keypair.secretKey.slice(0, 32));
    this.signature = Buffer.from(signature).toString("base64");
    this.signed = true;
  }

  public async signWithAdapter(adapter: Adapter) {
    let signature;
    let issuedAt = new Date(this.payload.iat * 1000).toISOString();
    let expirationTime = new Date(this.payload.exp * 1000).toISOString();
    const data = Buffer.from(await this.encode()).toString("hex");
    if ("signIn" in adapter) {
      const signinadapter = <SignInMessageSignerWalletAdapter>adapter;
      const signInOutput = await signinadapter.signIn({
        domain: this.payload.aud,
        issuedAt: issuedAt,
        address: this.payload.iss,
        expirationTime: expirationTime,
        nonce: data,
      });
      this.payload.account = signInOutput.account;
      let te = new TextDecoder();
      this.payload.rawMessage = te.decode(signInOutput.signedMessage);
      signature = signInOutput.signature;
    } else if ("signMessage" in adapter) {
      const message = ANBFSignInMessage(
        this.payload.aud,
        this.payload.iss,
        null,
        null,
        "1",
        null,
        data,
        issuedAt,
        expirationTime
      );
      const messageadapter = <MessageSignerWalletAdapter>adapter;
      this.payload.rawMessage = message;
      signature = await messageadapter.signMessage(Buffer.from(message));
    } else {
      throw new Error("Adapter does not support signing");
    }
    this.signature = Buffer.from(signature).toString("base64");
    this.signed = true;
  }

  public toString(): string {
    if (!this.signed) {
      throw new Error("JWT not signed");
    }
    return `${Buffer.from(JSON.stringify(this.header)).toString(
      "base64"
    )}.${Buffer.from(JSON.stringify(this.payload)).toString("base64")}.${
      this.signature
    }`;
  }
}
