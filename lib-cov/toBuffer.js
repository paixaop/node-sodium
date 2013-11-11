if (typeof global.__coverage__ === 'undefined') { global.__coverage__ = {}; }
if (!global.__coverage__['/Users/bmf/work/node-sodium/lib/toBuffer.js']) {
   global.__coverage__['/Users/bmf/work/node-sodium/lib/toBuffer.js'] = {"path":"/Users/bmf/work/node-sodium/lib/toBuffer.js","s":{"1":0,"2":1,"3":0,"4":0,"5":0,"6":0,"7":0,"8":0,"9":0,"10":0,"11":0,"12":0,"13":0,"14":0,"15":0,"16":0,"17":0},"b":{"1":[0,0],"2":[0,0],"3":[0,0],"4":[0,0],"5":[0,0],"6":[0,0]},"f":{"1":0},"fnMap":{"1":{"name":"toBuffer","line":20,"loc":{"start":{"line":20,"column":0},"end":{"line":20,"column":35}}}},"statementMap":{"1":{"start":{"line":11,"column":0},"end":{"line":11,"column":31}},"2":{"start":{"line":20,"column":0},"end":{"line":49,"column":1}},"3":{"start":{"line":22,"column":4},"end":{"line":47,"column":5}},"4":{"start":{"line":24,"column":8},"end":{"line":24,"column":37}},"5":{"start":{"line":25,"column":8},"end":{"line":25,"column":101}},"6":{"start":{"line":27,"column":8},"end":{"line":32,"column":9}},"7":{"start":{"line":28,"column":12},"end":{"line":28,"column":47}},"8":{"start":{"line":31,"column":12},"end":{"line":31,"column":104}},"9":{"start":{"line":35,"column":9},"end":{"line":47,"column":5}},"10":{"start":{"line":36,"column":8},"end":{"line":46,"column":9}},"11":{"start":{"line":37,"column":12},"end":{"line":37,"column":25}},"12":{"start":{"line":39,"column":13},"end":{"line":46,"column":9}},"13":{"start":{"line":40,"column":12},"end":{"line":45,"column":13}},"14":{"start":{"line":41,"column":16},"end":{"line":41,"column":41}},"15":{"start":{"line":44,"column":16},"end":{"line":44,"column":101}},"16":{"start":{"line":48,"column":4},"end":{"line":48,"column":89}},"17":{"start":{"line":51,"column":0},"end":{"line":51,"column":26}}},"branchMap":{"1":{"line":22,"type":"if","locations":[{"start":{"line":22,"column":4},"end":{"line":22,"column":4}},{"start":{"line":22,"column":4},"end":{"line":22,"column":4}}]},"2":{"line":24,"type":"binary-expr","locations":[{"start":{"line":24,"column":19},"end":{"line":24,"column":27}},{"start":{"line":24,"column":31},"end":{"line":24,"column":36}}]},"3":{"line":35,"type":"if","locations":[{"start":{"line":35,"column":9},"end":{"line":35,"column":9}},{"start":{"line":35,"column":9},"end":{"line":35,"column":9}}]},"4":{"line":36,"type":"if","locations":[{"start":{"line":36,"column":8},"end":{"line":36,"column":8}},{"start":{"line":36,"column":8},"end":{"line":36,"column":8}}]},"5":{"line":39,"type":"if","locations":[{"start":{"line":39,"column":13},"end":{"line":39,"column":13}},{"start":{"line":39,"column":13},"end":{"line":39,"column":13}}]},"6":{"line":39,"type":"binary-expr","locations":[{"start":{"line":39,"column":17},"end":{"line":39,"column":39}},{"start":{"line":39,"column":43},"end":{"line":39,"column":70}}]}}};
}
var __cov_NttSq1WFu52MEwDkks2x_g = global.__coverage__['/Users/bmf/work/node-sodium/lib/toBuffer.js'];
__cov_NttSq1WFu52MEwDkks2x_g.s['1']++;
var should = require('should');
function toBuffer(value, encoding) {
    __cov_NttSq1WFu52MEwDkks2x_g.f['1']++;
    __cov_NttSq1WFu52MEwDkks2x_g.s['3']++;
    if (typeof value === 'string') {
        __cov_NttSq1WFu52MEwDkks2x_g.b['1'][0]++;
        __cov_NttSq1WFu52MEwDkks2x_g.s['4']++;
        encoding = (__cov_NttSq1WFu52MEwDkks2x_g.b['2'][0]++, encoding) || (__cov_NttSq1WFu52MEwDkks2x_g.b['2'][1]++, 'hex');
        __cov_NttSq1WFu52MEwDkks2x_g.s['5']++;
        encoding.should.have.type('string').match(/^(?:utf8|ascii|binary|hex|utf16le|ucs2|base64)$/);
        __cov_NttSq1WFu52MEwDkks2x_g.s['6']++;
        try {
            __cov_NttSq1WFu52MEwDkks2x_g.s['7']++;
            return new Buffer(value, encoding);
        } catch (e) {
            __cov_NttSq1WFu52MEwDkks2x_g.s['8']++;
            throw new Error('[toBuffer] string value could not be converted to a buffer :' + e.message);
        }
    } else {
        __cov_NttSq1WFu52MEwDkks2x_g.b['1'][1]++;
        __cov_NttSq1WFu52MEwDkks2x_g.s['9']++;
        if (typeof value === 'object') {
            __cov_NttSq1WFu52MEwDkks2x_g.b['3'][0]++;
            __cov_NttSq1WFu52MEwDkks2x_g.s['10']++;
            if (Buffer.isBuffer(value)) {
                __cov_NttSq1WFu52MEwDkks2x_g.b['4'][0]++;
                __cov_NttSq1WFu52MEwDkks2x_g.s['11']++;
                return value;
            } else {
                __cov_NttSq1WFu52MEwDkks2x_g.b['4'][1]++;
                __cov_NttSq1WFu52MEwDkks2x_g.s['12']++;
                if ((__cov_NttSq1WFu52MEwDkks2x_g.b['6'][0]++, value instanceof Array) || (__cov_NttSq1WFu52MEwDkks2x_g.b['6'][1]++, value instanceof SlowBuffer)) {
                    __cov_NttSq1WFu52MEwDkks2x_g.b['5'][0]++;
                    __cov_NttSq1WFu52MEwDkks2x_g.s['13']++;
                    try {
                        __cov_NttSq1WFu52MEwDkks2x_g.s['14']++;
                        return new Buffer(value);
                    } catch (e) {
                        __cov_NttSq1WFu52MEwDkks2x_g.s['15']++;
                        throw new Error('[toBuffer] Array could not be converted to a buffer :' + e.message);
                    }
                } else {
                    __cov_NttSq1WFu52MEwDkks2x_g.b['5'][1]++;
                }
            }
        } else {
            __cov_NttSq1WFu52MEwDkks2x_g.b['3'][1]++;
        }
    }
    __cov_NttSq1WFu52MEwDkks2x_g.s['16']++;
    throw new Error('[toBuffer] unsupported type in value. Use Buffer, string or Array');
}
__cov_NttSq1WFu52MEwDkks2x_g.s['17']++;
module.exports = toBuffer;
