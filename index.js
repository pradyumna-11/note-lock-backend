const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const dbPath = path.join(__dirname, "storage.db");
const uuid = require("uuid");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const cors = require("cors");
const bodyParser = require("body-parser");
const crypto = require("crypto");
const algorithm = "aes-256-ctr";
const secretKey = crypto.randomBytes(32).toString("hex");
const iv = crypto.randomBytes(16);
const app = express();

app.use(express.json());
app.use(cors());
app.use(bodyParser.json());

let db = null;

const encrypt = (text) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(
    algorithm,
    Buffer.from(secretKey, "hex"),
    iv
  );
  const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);

  // Combine IV and encrypted content into a single string
  return iv.toString("hex") + ":" + encrypted.toString("hex");
};

const decrypt = (hash) => {
  const [iv, content] = hash.split(":");
  const decipher = crypto.createDecipheriv(
    algorithm,
    Buffer.from(secretKey, "hex"),
    Buffer.from(iv, "hex")
  );
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(content, "hex")),
    decipher.final(),
  ]);

  return decrypted.toString();
};

const initializeServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(3001, () =>
      console.log("Server running successfully at https://localhost:3001")
    );
  } catch (e) {
    console.log(`Error occured as ${e}`);
    process.exit(1);
  }
};

initializeServer();

const verifyJwtToken = (request, res, next) => {
  let jwtToken;
  const authHeaders = request.headers["authorization"];
  if (authHeaders !== undefined) {
    jwtToken = authHeaders.split(" ")[1];
  }
  if (jwtToken === undefined) {
    res.status(401);
    res.send("User not authenticated");
  } else {
    jwt.verify(jwtToken, "MY_SECRET_TOKEN", async (error, payload) => {
      if (error) {
        res.status(401);
        res.send("Invalid JWT Token");
      } else {
        request.userId = payload.userId;

        next();
      }
    });
  }
};

// sign-up api call
app.post("/sign-up", async (req, res) => {
  const { username, email, password } = req.body;
  const getUser = `SELECT * FROM USERS WHERE username = ? OR email = ?`;
  const userExistDetails = await db.get(getUser, [username, email]);
  if (userExistDetails === undefined) {
    const newUserId = uuid.v4();
    const hashedPassword = await bcrypt.hash(password, 10);
    const newUserEntryQuery = `
      INSERT INTO USERS(user_id,username,email,password_hash)
      VALUES(?, ?, ?, ?)
    `;
    await db.run(newUserEntryQuery, [
      newUserId,
      username,
      email,
      hashedPassword,
    ]);

    res.status(200).send({ Response: "Account created successfully" });
  } else {
    if (username === userExistDetails.username) {
      res.status(400).send({ Error: "Username already exists" });
    } else if (email === userExistDetails.email) {
      res.status(400).send({ Error: "User email already exists" });
    } else {
      res.status(400).send({ Error: "User already exists" });
    }
  }
});

//login api call
app.post("/login", async (request, response) => {
  const { username, password } = request.body;
  const getUserDetailsQuery = `SELECT * FROM USERS WHERE username = ?`;
  const userDetails = await db.get(getUserDetailsQuery, [username]);

  if (userDetails === undefined) {
    response.status(400).send({ Error: "Username and password didn't match" });
  } else {
    const isPasswordMatched = await bcrypt.compare(
      password,
      userDetails.password_hash
    );
    if (isPasswordMatched === true) {
      const payload = {
        userId: userDetails.user_id,
      };
      const jwtToken = jwt.sign(payload, "MY_SECRET_TOKEN");
      const updateUserJwtTokenQuery = `
        UPDATE USERS SET jwt_token = ? WHERE username = ?
      `;
      await db.run(updateUserJwtTokenQuery, [jwtToken, username]);

      response.status(200).send({ jwtToken });
    } else {
      response.status(400).send({ Error: "Incorrect password" });
    }
  }
});

//verify password api call
app.post(
  "/verify-password/:userId",
  verifyJwtToken,
  async (request, response) => {
    const { userId } = request.params;
    const { password } = request.body;
    const getUserDetails = `SELECT * FROM USERS WHERE user_id = ?`;
    try {
      const userDetailsResponse = await db.get(getUserDetails, [userId]);
      const isPasswordMatch = await bcrypt.compare(
        password,
        userDetailsResponse.password_hash
      );
      if (isPasswordMatch) {
        response.status(200).send({ Success: "Password is correct" });
      } else {
        response.status(400).send({ Failure: "Password Incorrect" });
      }
    } catch (e) {
      response.status(500).send({ Error: `Error at ${e.message}` });
    }
  }
);

//update user account password
app.post("/forget-password", async (request, response) => {
  const { email, password } = request.body;
  const updatedHashedPassword = await bcrypt.hash(password, 10);
  const updateUserAccountPasswordQuery = `
    UPDATE USERS SET password_hash=? WHERE email = ?
  `;
  try {
    await db.run(updateUserAccountPasswordQuery, [
      updatedHashedPassword,
      email,
    ]);
    response.status(200).send({ Success: "Password updated successfully" });
  } catch (e) {
    response.status(500).send({ Error: `Error: ${e.message}` });
  }
});

// retrive users data api call
app.get("/", verifyJwtToken, async (req, res) => {
  const getAllUsersDataQuery = `SELECT * FROM USERS`;
  const dbResponse = await db.all(getAllUsersDataQuery);
  res.send(dbResponse);
});

//get user id
app.get("/get-user-id", verifyJwtToken, async (request, response) => {
  let jwtToken;
  const authHeaders = request.headers["authorization"];
  if (authHeaders !== undefined) {
    jwtToken = authHeaders.split(" ")[1];
  }
  const getUserIdQuery = `SELECT * FROM USERS WHERE jwt_token = ?`;
  try {
    const userIdResponse = await db.get(getUserIdQuery, [jwtToken]);
    response.status(200).send({ userId: `${userIdResponse.user_id}` });
  } catch (e) {
    response.status(400).send({ Error: `Error: ${e.message}` });
  }
});

//get all notes api call
app.get("/notes/", verifyJwtToken, async (request, response) => {
  let jwtToken;
  const authHeaders = request.headers["authorization"];
  if (authHeaders !== undefined) {
    jwtToken = authHeaders.split(" ")[1];
  }
  const getAllUserNotesQuery = `
    SELECT * FROM NOTES WHERE user_id = (SELECT user_id FROM USERS WHERE jwt_token = ?)
  `;
  try {
    const allUserNotes = await db.all(getAllUserNotesQuery, [jwtToken]);
    response.status(200).send({ data: allUserNotes });
  } catch (e) {
    response.status(400).send({ Error: `Error: ${e.message}` });
  }
});

//get note details
app.get("/notes/:noteId", verifyJwtToken, async (request, response) => {
  const { noteId } = request.params;
  const getNoteDetailsQuery = `SELECT * FROM notes WHERE note_id = ?`;
  try {
    const noteItemDetailsResponse = await db.get(getNoteDetailsQuery, [noteId]);
    response.status(200).send({ data: noteItemDetailsResponse });
  } catch (e) {
    response.status(500).send({ Error: `Error: ${e.message}` });
  }
});

//insert new note
app.post("/new-note/:userId", verifyJwtToken, async (req, res) => {
  const { title, description } = req.body;
  const { userId } = req.params;
  const newNoteId = uuid.v4();
  const addNewNoteQuery = `
    INSERT INTO NOTES (note_id, title, user_id, description)
    VALUES(?, ?, ?, ?)
  `;
  try {
    await db.run(addNewNoteQuery, [newNoteId, title, userId, description]);
    res.send("New note added successfully");
  } catch (error) {
    console.error(`Error executing query: ${error.message}`);
    res.status(500).send("Error adding new note");
  }
});

//update note
app.put("/new-note/:noteId", verifyJwtToken, async (request, response) => {
  const { noteId } = request.params;
  const { title, description } = request.body;
  const updateNoteQuery = `
    UPDATE notes SET title=?, description=? WHERE note_id=?
  `;
  try {
    await db.run(updateNoteQuery, [title, description, noteId]);
    response.status(200).send({ success: "Note updated successfully" });
  } catch (error) {
    response.status(500).send({ error: `Error: ${error.message}` });
  }
});

//delete note
app.delete("/new-note/:noteId", verifyJwtToken, async (request, response) => {
  const { noteId } = request.params;
  const deleteNoteQuery = `DELETE FROM notes WHERE note_id=?`;
  try {
    await db.run(deleteNoteQuery, [noteId]);
    response.status(200).send({ success: "Note deleted successfully" });
  } catch (error) {
    response.status(500).send({ error: `Error: ${error.message}` });
  }
});

//getPasswordsData
app.get("/passwords/:userId", verifyJwtToken, async (request, response) => {
  const { userId } = request.params;
  const getAllPasswordsQuery = `
    SELECT * FROM PASSWORDS WHERE USER_ID = '${userId}';
  `;
  try {
    const allPasswordsData = await db.all(getAllPasswordsQuery);
    response.status(200).send({ data: allPasswordsData });
  } catch (e) {
    response.status(400).send(`Error at ${e.message}`);
  }
});

app.get("/password/:passwordId", verifyJwtToken, async (request, response) => {
  const { passwordId } = request.params;
  const getPasswordItemQuery = `
    SELECT * FROM PASSWORDS WHERE password_id = ?;
  `;
  try {
    const passwordItemData = await db.get(getPasswordItemQuery, [passwordId]);
    const decryptedPassword = decrypt(passwordItemData.password);
    passwordItemData.password = decryptedPassword;
    response.status(200).send({ data: passwordItemData });
  } catch (e) {
    response.status(400).send(`Error at ${e.message}`);
  }
});

// Add password
app.post("/passwords/:userId", verifyJwtToken, async (request, response) => {
  const { userId } = request.params;
  const { username = "", website = "", password = "" } = request.body;
  const newPasswordId = uuid.v4();
  const hashedPassword = encrypt(password);
  const addNewPasswordQuery = `
    INSERT INTO PASSWORDS(password_id, user_id, username, website, password)
    VALUES (?, ?, ?, ?, ?);
  `;
  try {
    await db.run(addNewPasswordQuery, [
      newPasswordId,
      userId,
      username,
      website,
      hashedPassword,
    ]);
    response.status(200).send({ Success: "New password added successfully" });
  } catch (e) {
    response.status(400).send(`Error occurred: ${e.message}`);
  }
});

// Update password
app.put("/passwords/:passwordId", verifyJwtToken, async (request, response) => {
  let { username = "", password = "" } = request.body;
  const { passwordId } = request.params;
  const getPasswordItemDetailsQuery = `
    SELECT * FROM PASSWORDS WHERE password_id = ?;
  `;
  try {
    const passwordItemDetails = await db.get(getPasswordItemDetailsQuery, [
      passwordId,
    ]);
    if (passwordItemDetails === undefined) {
      response.status(400).send({ Error: "Invalid Password ID" });
    } else {
      username = username === "" ? passwordItemDetails.username : username;
      password =
        password === "" ? passwordItemDetails.password : encrypt(password);

      const updatePasswordQuery = `
        UPDATE PASSWORDS SET username = ?, password = ? WHERE password_id = ?;
      `;
      await db.run(updatePasswordQuery, [username, password, passwordId]);
      response.status(200).send({ Success: "Updated password successfully" });
    }
  } catch (e) {
    response.status(400).send(`Error at ${e.message}`);
  }
});

// Delete password
app.delete(
  "/passwords/:passwordId",
  verifyJwtToken,
  async (request, response) => {
    const { passwordId } = request.params;
    const deletePasswordQuery = `
    DELETE FROM PASSWORDS WHERE password_id = ?;
  `;
    try {
      await db.run(deletePasswordQuery, [passwordId]);
      response.status(200).send({ Success: "Successfully deleted password" });
    } catch (e) {
      response.status(500).send({ Error: `Error at ${e.message}` });
    }
  }
);

// OTP send API
app.post("/send-otp", async (request, response) => {
  const { email } = request.body;
  const verifyUserEmailQuery = `
    SELECT * FROM USERS WHERE email = ?;
  `;
  try {
    const verifyUserEmailDetails = await db.get(verifyUserEmailQuery, [email]);
    if (verifyUserEmailDetails === undefined) {
      response
        .status(400)
        .send({ Error: "No account has been created on this email." });
    } else {
      let transporter = nodemailer.createTransport({
        service: "Gmail",
        auth: {
          user: "central.processing.unit.0506@gmail.com",
          pass: "chhe fvhc jyvb gdyt",
        },
      });

      let otp = Math.floor(Math.random() * 1000000);

      let mailOptions = {
        from: "central.processing.unit.0506@gmail.com",
        to: email,
        subject:
          "Your verification code regarding password manager web application",
        text: `Your Google account verification code is: '${otp}'. Please don't share it with anyone.`,
      };

      let info = await transporter.sendMail(mailOptions);
      console.log("Email sent: " + info.response);
      response.status(200).send({ Success: `Email sent: ${info.response}` });

      const checkUserEmailInOtpQuery = `
        SELECT * FROM OTPS WHERE email = ?;
      `;
      const checkUserEmailInOtpDetails = await db.get(
        checkUserEmailInOtpQuery,
        [email]
      );
      if (checkUserEmailInOtpDetails === undefined) {
        const insertUserEmailAndOtpQuery = `
          INSERT INTO OTPS(email, otp) VALUES(?, ?);
        `;
        await db.run(insertUserEmailAndOtpQuery, [email, otp]);
      } else {
        const updateUserEmailOtpQuery = `
          UPDATE OTPS SET otp = ? WHERE email = ?;
        `;
        await db.run(updateUserEmailOtpQuery, [otp, email]);
      }
    }
  } catch (error) {
    console.error(error);
    response
      .status(500)
      .send({ Error: `Error sending email: ${error.message}` });
  }
});

// Get all OTPs
app.get("/all-otps", async (request, response) => {
  const getAllOtpsQuery = `
    SELECT * FROM OTPS;
  `;
  try {
    const allOtpsDetails = await db.all(getAllOtpsQuery);
    response.send(allOtpsDetails);
  } catch (e) {
    response.status(400).send({ Error: `Error at ${e.message}` });
  }
});

//otp check api
app.post("/verify-otp", async (request, response) => {
  const { email, userOtp } = request.body;
  const getUserOtpsQuery = `
    SELECT * FROM OTPS WHERE email = ?;
  `;
  const getUserOtpsDetails = await db.get(getUserOtpsQuery, [email]);
  if (getUserOtpsDetails.otp === parseInt(userOtp)) {
    response.status(200).send({ Success: "Correct Otp verified" });
  } else {
    response.status(400).send({ Error: "Incorrect OTP" });
  }
});
