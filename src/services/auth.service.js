const httpStatus = require('http-status');
const moment = require('moment');
const nacl = require('tweetnacl');
const jwt = require('jsonwebtoken');
const bs58 = require('bs58');
const tokenService = require('./token.service');
const userService = require('./user.service');
const Token = require('../models/token.model');
const ApiError = require('../utils/ApiError');
const { tokenTypes } = require('../config/tokens');
const config = require('../config/config');
const logger = require('../config/logger');

/**
 * Login with username and password
 * @param {string} email
 * @param {string} password
 * @returns {Promise<User>}
 */
const loginUserWithEmailAndPassword = async (email, password) => {
  const user = await userService.getUserByEmail(email);
  if (!user || !(await user.isPasswordMatch(password))) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Incorrect email or password');
  }
  return user;
};

/**
 * Logout
 * @param {string} refreshToken
 * @returns {Promise}
 */
const logout = async (refreshToken) => {
  const refreshTokenDoc = await Token.findOne({ token: refreshToken, type: tokenTypes.REFRESH, blacklisted: false });
  if (!refreshTokenDoc) {
    throw new ApiError(httpStatus.NOT_FOUND, 'Not found');
  }
  await refreshTokenDoc.remove();
};

/**
 * Refresh auth tokens
 * @param {string} refreshToken
 * @returns {Promise<Object>}
 */
const refreshAuth = async (refreshToken) => {
  try {
    const refreshTokenDoc = await tokenService.verifyToken(refreshToken, tokenTypes.REFRESH);
    const user = await userService.getUserById(refreshTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await refreshTokenDoc.remove();
    return tokenService.generateAuthTokens(user);
  } catch (error) {
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Please authenticate');
  }
};

/**
 * Reset password
 * @param {string} resetPasswordToken
 * @param {string} newPassword
 * @returns {Promise}
 */
const resetPassword = async (resetPasswordToken, newPassword) => {
  try {
    const resetPasswordTokenDoc = await tokenService.verifyToken(resetPasswordToken, tokenTypes.RESET_PASSWORD);
    const user = await userService.getUserById(resetPasswordTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await userService.updateUserById(user.id, { password: newPassword });
    await Token.deleteMany({ user: user.id, type: tokenTypes.RESET_PASSWORD });
  } catch (error) {
    logger.error('resetPassword err: ', error);
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Password reset failed');
  }
};

/**
 * Verify email
 * @param {string} verifyEmailToken
 * @returns {Promise}
 */
const verifyEmail = async (verifyEmailToken) => {
  try {
    const verifyEmailTokenDoc = await tokenService.verifyToken(verifyEmailToken, tokenTypes.VERIFY_EMAIL);
    const user = await userService.getUserById(verifyEmailTokenDoc.user);
    if (!user) {
      throw new Error();
    }
    await Token.deleteMany({ user: user.id, type: tokenTypes.VERIFY_EMAIL });
    await userService.updateUserById(user.id, { isEmailVerified: true });
  } catch (error) {
    logger.error('verifyEmail err: ', error);
    throw new ApiError(httpStatus.UNAUTHORIZED, 'Email verification failed');
  }
};

/**
 * Get Sign message
 * @param {ObjectId} id
 * @returns {string}
 */
const getSignMessage = (id) => {
  logger.info('getSignMessage, id: %s', id);
  return tokenService.generateToken(
    id,
    moment().add(config.jwt.verifySignWalletExpirationMinutes, 'minutes'),
    tokenTypes.VERIFY_WALLET,
    config.jwt.walletSignSecret,
    config.jwt.walletSignSecret
  );
};

/**
 * linkPhantomWallet
 * @param {ObjectId} userId
 * @param {Object} body
 * @returns {Promise}
 */
const linkPhantomWallet = async (userId, body) => {
  logger.info('linkPhantomWallet, id: %s, req: %s', userId, body);
  const user = await userService.getUserById(userId);
  if (!user) {
    logger.info('User not found, id: ', userId);
    throw new ApiError(httpStatus.NOT_FOUND, 'User not found');
  }
  try {
    jwt.verify(body.originMessage, config.jwt.walletSignSecret, null, null);
    const originMsg = Buffer.from(body.originMessage);
    const b = Buffer.from(body.signedMessage, 'base64');
    const addr = bs58.decode(body.walletAddress);
    if (!nacl.sign.detached.verify(originMsg, b, addr)) {
      throw new ApiError(httpStatus.BAD_REQUEST, 'Invalid sign message');
    }
  } catch (e) {
    logger.error('linkPhantomWallet err, id: %s, req: %s, err: %s', userId, body, e);
    throw new ApiError(httpStatus.BAD_REQUEST, 'Invalid sign message');
  }
  user.phantomAddress = body.walletAddress;
  await user.save();
};

module.exports = {
  loginUserWithEmailAndPassword,
  logout,
  refreshAuth,
  resetPassword,
  verifyEmail,
  getSignMessage,
  linkPhantomWallet,
};
