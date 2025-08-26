import { Client, Users, ID, Databases, Query } from 'node-appwrite';

class AppwriteService {
  constructor() {
    const client = new Client();
    client
      .setEndpoint(
        process.env.APPWRITE_ENDPOINT ?? 'https://cloud.appwrite.io/v1'
      )
      .setProject(process.env.APPWRITE_FUNCTION_PROJECT_ID)
      .setKey(process.env.APPWRITE_API_KEY);

    this.users = new Users(client);
    this.databases = new Databases(client);
  }

  async prepareUser(email) {
    const response = await this.users.list([ Query.equal('email', email), Query.limit(1) ]);
    let user = response.users[0] ?? null;

    if(!user) {
      user = await this.users.create(ID.unique(), email);
    }
    
    return user;
  }

  async createSessionToken(userId) {
    return await this.users.createToken(userId, 64, 60);
  }

  async createChallenge(userId, token) {
    return await this.databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID_AUTH_PASSKEY_CHALLENGES,
      ID.unique(),
      {
        userId: userId,
        token
      }
    );
  }

  async getChallenge(challengeId) {
    return await this.databases.getDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID_AUTH_PASSKEY_CHALLENGES,
      challengeId
    );
  }

  async deleteChallenge(challengeId) {
    return await this.databases.deleteDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID_AUTH_PASSKEY_CHALLENGES,
      challengeId
    );
  }

  async createCredentials(userId, credentials) {
    return await this.databases.createDocument(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID_AUTH_PASSKEY_CREDENTIALS,
      ID.unique(),
      {
        userId,
        credentials: JSON.stringify(credentials)
      }
    );
  }

  async getCredential(userId) {
    const documents = (await this.databases.listDocuments(
      process.env.APPWRITE_DATABASE_ID,
      process.env.APPWRITE_COLLECTION_ID_AUTH_PASSKEY_CREDENTIALS,
      [
        Query.equal('userId', userId),
        Query.limit(1)
      ]
    )).documents;

    return documents[0];
  }
}

export default AppwriteService;
