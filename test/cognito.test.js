'use strict';

const Cognito = require('../lib/cognito')

const UserPoolId = process.env.AWS_COGNITO_USERPOOLID
const ClientId = process.env.AWS_COGNITO_CLIENTID
const IdentityPoolId = process.env.AWS_COGNITO_IDENTITYPOOLID
const CognitoUsername = process.env.AWS_COGNITO_USER_NAME
const CognitoPassword = process.env.AWS_COGNITO_USER_PASSWORD

var testCognito = new Cognito({
  UserPoolId: UserPoolId, 
  ClientId: ClientId,
  IdentityPoolId: IdentityPoolId
})

describe('AWS Cognito Preauthentication States', () => {
  it ('it should have a session as invalid', done => {
    expect(testCognito.isSessionValid()).toBe(false)
    done()
  })
  it ('it should throw error if trying to get token before authenticated', done => {
    expect(() => {
      testCognito.getIdToken()
    }).toThrow()
    done()
  })
})
describe('AWS Cognito Authentication', () => {
  it ('should authenticate a valid user', done => {
    testCognito.auth({
      Username: CognitoUsername,   
      Password: CognitoPassword 
    })
    .then((data) => {
      expect(testCognito.isSessionValid()).toBe(true)
      expect(testCognito.getIdToken()).toHaveProperty("token")
      expect(testCognito.getExpDate() > new Date()).toBe(true)
      done()
    })
  }) 
  it ('should auth the current user', done => {
    testCognito.authCurrentUser()
    .then((session) => {
      expect(testCognito.isSessionValid()).toBe(true)
      expect(testCognito.getIdToken()).toHaveProperty("token")
      expect(testCognito.getExpDate() > new Date()).toBe(true)
      done()
    })
    .catch((err) => {
      console.log("ERR", err)
      
      done()
    })
  })
  it ('should refresh the session', done => {
    var expdate1 = testCognito.getExpDate()
    testCognito.refresh()
    .then((session) => {
      var expdate2 = testCognito.getExpDate()
      //console.log("EXP1", expdate1, "EXP2", expdate2)
      expect(expdate2 >= expdate1).toBe(true)
      done()
    })
    .catch((err) => {
      console.log(err, err.stack)
      done()
    })
  })
})
describe('AWS Cognito User Attributes', () => {
  it ('should get the user attributes from a valid session', done => {
    testCognito.userAttributes()
    .then((attributes) => {
      expect(attributes).toMatchObject({
        "email": "danieljyoo@gmail.com",
        "sub": expect.anything()
      })
      done()
    })
  })
})
describe("AWS Cognito Sign out", () => {
  it ('should sign out the user and invalidate the sesssion', done => {
    testCognito.signOut()
    expect(testCognito.isSessionValid()).toBe(false)
    done()
  })
  it ('should be NOT be able to sign the user back in from storage', done => {
    testCognito.authCurrentUser()
    .then((session) => {
      // should not be able to sign in from current user after a signOut
      expect(session).toBeFalsy()
      done()
    })
    .catch((err) => {
      expect(err.message).toBe("No current user")
      done()
    })
  })
})




