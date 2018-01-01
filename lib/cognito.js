'use strict';

// https://github.com/aws/amazon-cognito-identity-js

const ACI = require('amazon-cognito-identity-js')
const jwt_decode = require('jwt-decode');

/// { AuthenticationDetails, CognitoUserPool, CognitoUserAttribute, CognitoUser } 
 
class Cognito {
  
  constructor(config) {
    this.AWSRegion = config.AWSRegion
    this.UserPoolId = config.UserPoolId
    this.ClientId = config.ClientId
    this.IdentityPoolId = config.IdentifyPoolId
    this.IdentityPoolKey = `cognito-idp.${this.AWSRegion}.amazonaws.com/${this.UserPoolId}` 
    
    this.userPool = new ACI.CognitoUserPool({
      UserPoolId: this.UserPoolId,
      ClientId: this.ClientId
    })
    
    this.user = null
    this.session = null
    this.userattributes = {}
  }
  
  createCognitoUser(authData) {
    return new ACI.CognitoUser({
      Username: authData.Username,
      Pool: this.userPool
    })
  }

  createCognitoAuthenticationDetails(authData) {
    return new ACI.AuthenticationDetails(authData)    
  }
  
  isSessionValid() {
    return this.session && this.session.isValid() || false
  }
  
  getIdToken() {
    if (!this.isSessionValid()) {
      throw new Error('No valid user session')
    }
    var idtoken = this.session.getIdToken()
    var exp = idtoken.getExpiration()
    var expdate = new Date(0)
    expdate.setUTCSeconds(exp)
    return {
      token: idtoken.jwtToken,
      expdate: expdate,
      payload: idtoken.payload,
    }
  }
  
  getExpDate() {
    return this.getIdToken().expdate
  }
  
  // AWS.config.credentials = [return of this method]
  getAWSIdentityCredentials() {
    if (!this.isSessionValid()) {
      throw new Error('No valid user session')
    }
    var login = {}
    login[this.UserPoolId] = this.getIdToken().token
  
    return new AWS.CognitoIdentityCredentials({
      IdentityPoolId: this.IdentityPoolId, 
      Logins: login
    })
  }
  
  currentUser() {
    return this.userPool.getCurrentUser()
  }
  
  currentSession() {
    return new Promise((resolve, reject) => {
      this.user.getSession((err, session) => {
        if (err) {
          reject(err)
          return
        }
        resolve(session)
        return
      })
    })
  }
  
  authCurrentUser() {
    return new Promise((resolve, reject) => {
      var user = this.currentUser()
      if (!user) {
        reject(new Error('No current user'))
        return
      }  
      this.user = user
      this.currentSession()
      .then((session) => {
        this.session = session
        return this.userAttributes()
      })
      .then((attributes) => {
        this.userattributes = attributes
        var idtoken = this.getIdToken()
        resolve({ 
          status: 'success',
          token: idtoken.token,
          decoded: idtoken.payload,
          expiration: idtoken.expdate 
        })
        return
      })
      .catch((err) => {
        reject(err)
        return
      })
    })
  }
  
  // { Username: <email>, Password: <pass> }
  auth(authData) {
    return new Promise((resolve, reject) => {
      this.user = this.createCognitoUser(authData)
      var authenticationDetails = this.createCognitoAuthenticationDetails(authData)
      this.user.authenticateUser(authenticationDetails, {
        onSuccess: (session) => {
          this.session = session
          resolve(session)
          return
        },
        onFailure: function(err) {
          reject({ status: 'failure', error: err })
          return
        },
        newPasswordRequired: function(userAttributes, requiredAttributes) {
          reject({ status: 'newPasswordRequired', data: { userAttributes, requiredAttributes }})
          return
        }
      })
    })
    .then((session) => {
      return this.userAttributes()
    })
    .then((attributes) => {
      this.userattributes = attributes
      var idtoken = this.getIdToken()
      return Promise.resolve({ 
        status: 'success',
        token: idtoken.token,
        decoded: idtoken.payload,
        expiration: idtoken.expdate 
      })
    })
  }
  
  
  
  userAttributes() {
    return new Promise((resolve, reject) => {
      this.user.getUserAttributes((err, result) => {
        if (err) {
          reject(err)
          return
        }
        var ret = { }
        for (var i = 0; i < result.length; i++) {
          ret[result[i].getName()] = result[i].getValue();
        }
        resolve(ret)
        return
      })
    })
  }
  
  refresh() {
    if (!this.session) {
      throw new Error('No session')
    }
    var refreshToken = this.session.refreshToken
    return new Promise((resolve, reject) => {
      this.user.refreshSession(refreshToken, (err, session) => {
        if (err) {
          reject(err)
          return
        }
        this.session = session
        resolve(session)
        return
      })  
    })
  }
  
  signOut() {
    if (!this.user) {
      throw new Error("No user")
    }
    this.user.signOut()
    this.user = null
    this.session = null
    // also userPool.getCurrentUser() will return null as well
  }
}

module.exports = Cognito


