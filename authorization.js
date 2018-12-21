const crypto = require('crypto-js');

function authorize() {
	var signatureArray = []
	var timeStamp = Math.floor(Date.now()/1000)
	var nonce = (Math.random().toString(36).substr(2))
	var apiId = '95W9R2Bwt5TfBVmEMMdg7gaKJXesme0Y'  //需要申请
	var apiSecret = 'J8ZxMJmevwpdYCe2IUCI62ffqa9weHnM' //需要申请
	signatureArray.push(timeStamp, nonce, apiId)
	var signatureString = signatureArray.sort().join('')
	var hmac = crypto.HmacSHA256(signatureString, apiSecret)
	var authorization = 'key=' + apiId + ',timestamp=' + timeStamp + ',nonce=' + nonce + ',signature=' + hmac
	return authorization
}