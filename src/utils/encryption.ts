import crypto from "crypto";

const algo = "aes-256-gcm";

function md5(input: string): string {
  const hash = crypto.createHash("md5");
  hash.update(input);
  return hash.digest("hex");
}

interface EncryptedMessage {
  secretDescriptor: string;
  cipher: Buffer;
  initialisationVector: Buffer;
}

function isValidSecret(string: String): boolean {
  return string.length === 32;
}

function getSecretDescriptor(secret: string): string {
  return md5(secret).slice(0, 4);
}

function generateInitialisationVector() {
  return crypto.randomBytes(16);
}

function packMessage(message: EncryptedMessage) {
  return [
    message.secretDescriptor,
    message.initialisationVector.toString("base64"),
    message.cipher.toString("base64"),
  ].join(":");
}

function unpackMessage(message: string): EncryptedMessage {
  const [secretDescriptor, initialisationVector, cipher] = message.split(":");
  return {
    secretDescriptor,
    initialisationVector: Buffer.from(initialisationVector, "base64"),
    cipher: Buffer.from(cipher, "base64"),
  };
}

export default class Encryptor {
  private readonly decryptionSecretsByDescriptor: Record<string, string> = {};

  constructor(
    private readonly encryptionSecret: string,
    decryptionSecret: string = encryptionSecret
  ) {
    if (!isValidSecret(encryptionSecret)) {
      throw new Error(
        `\`encryptionSecret\` needs to be 32 characters, but was ${encryptionSecret.length} characters.`
      );
    }

    if (!isValidSecret(decryptionSecret)) {
      throw new Error(
        `decryptionSecret needs to be 32 characters, but was ${decryptionSecret.length} characters.`
      );
    }

    const id = getSecretDescriptor(decryptionSecret);
    this.decryptionSecretsByDescriptor[id] = decryptionSecret;
  }

  public encrypt(input: string): string {
    const secretDescriptor = getSecretDescriptor(this.encryptionSecret);
    const iv = generateInitialisationVector();

    const cipher = crypto.createCipheriv(algo, this.encryptionSecret, iv);

    const encryptedInput = Buffer.concat([
      cipher.update(input, "utf8"),
      cipher.final(),
    ]);

    return packMessage({
      cipher: encryptedInput,
      initialisationVector: iv,
      secretDescriptor: secretDescriptor,
    });
  }

  public decrypt(string: string): string {
    const { cipher, initialisationVector, secretDescriptor } = unpackMessage(
      string
    );

    const key = this.decryptionSecretsByDescriptor[secretDescriptor];
    if (!key) {
      throw new Error("Could not decrypt: No matching secret.");
    }

    const decipher = crypto.createDecipheriv(algo, key, initialisationVector);

    return decipher.update(cipher, "hex", "utf8");
  }
}