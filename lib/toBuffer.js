/**
 * toBuffer Module
 * Convert value into a buffer
 *
 * @name node-sodium
 * @author bmf
 * @date 11/5/13
 * @version $
 */
/* jslint node: true */
'use strict';

/**
 * Convert value into a buffer
 *
 * @param {String|Buffer|Array} value  a buffer, and array of bytes or a string that you want to convert to a buffer
 * @param {String} [encoding]          encoding to use in conversion if value is a string. Defaults to 'hex'
 * @returns {*}
 */
function toBuffer(value, encoding) {

    if( typeof value === 'string') {

        encoding = encoding || 'hex';
        encoding.should.have.type('string').match(/^(?:utf8|ascii|binary|hex|utf16le|ucs2|base64)$/);

        try {
            return new Buffer(value, encoding);
        }
        catch (e) {
            throw new Error('[toBuffer] string value could not be converted to a buffer :' + e.message);
        }

    }
    else if( typeof value === 'object' ) {
        if( Buffer.isBuffer(value) ) {
            return value;
        }
        else if( value instanceof Array ) {
            try {
                return new Buffer(value);
            }
            catch (e) {
                throw new Error('[toBuffer] Array could not be converted to a buffer :' + e.message);
            }
        }
    }
    throw new Error('[toBuffer] unsupported type in value. Use Buffer, string or Array');
}

module.exports = toBuffer;