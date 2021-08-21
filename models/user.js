/** User class for message.ly */
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const db = require("../db");
const ExpressError = require("../expressError");
const { SECRET_KEY, BCRYPT_WORK_FACTOR } = require("../config");
const { authenticateJWT } = require("../middleware/auth");


/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    const today = new Date();
    const salt = await bcrypt.genSalt(BCRYPT_WORK_FACTOR);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    const results = await db.query(
      `INSERT INTO users (
        username, password, first_name, last_name, phone, join_at, last_login_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone, today, today]
    );

    return results.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const results = await db.query(
      `SELECT * FROM users
       WHERE username = $1`,
      [username]);
    const user = results.rows[0]
    return await bcrypt.compare(password, user.password);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 
    const today = new Date();
    await db.query(
      `UPDATE users 
        SET last_login_at=$1 
        WHERE username=$2`,
      [today, username]
    );

  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    const userQuery = await db.query(
      `SELECT username, first_name, last_name, phone
       FROM users`
    );
    if (!userQuery.rows[0]) {
      throw new ExpressError("No users selected", 400);
    }
    return userQuery.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    const userQuery = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
       FROM users
       WHERE username=$1`,
       [username]
    );
    if (!userQuery.rows[0]) {
      throw new ExpressError("No users selected", 400);
    }
    return userQuery.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    const msgQuery = await db.query(
      `SELECT id, body, sent_at, read_at, to_username AS to_user
       FROM messages
       WHERE from_username = $1`,
      [username]
    );
    const messages = msgQuery.rows

    const promiseArr = []
    messages.forEach( msg => {
        promiseArr.push(
          db.query(
            `SELECT username, first_name, last_name, phone
             FROM users
             WHERE username = $1`,
            [msg.to_user]
          )
        );
    });

    const msgsToUser = await Promise.all(promiseArr)
      .catch(err => console.log(err));
    messages.forEach( (message, idx) => {
      message.to_user = msgsToUser[0].rows[idx];
    })
    
    if (!msgQuery.rows[0]) {
      throw new ExpressError("No messages available/selected", 400);
    }
    
    return messages;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    const msgQuery = await db.query(
      `SELECT id, body, sent_at, read_at, from_username AS from_user
       FROM messages
       WHERE to_username = $1`,
      [username]
    );
    const messages = msgQuery.rows;

    const promiseArr = [];
    messages.forEach((msg) => {
      promiseArr.push(
        db.query(
          `SELECT username, first_name, last_name, phone
             FROM users
             WHERE username = $1`,
          [msg.from_user]
        )
      );
    });

    const msgsToUser = await Promise.all(promiseArr).catch((err) =>
      console.log(err)
    );
    messages.forEach((message, idx) => {
      message.from_user = msgsToUser[0].rows[idx];
    });

    if (!msgQuery.rows[0]) {
      throw new ExpressError("No messages available/selected", 400);
    }
    return msgQuery.rows;}
}


module.exports = User;