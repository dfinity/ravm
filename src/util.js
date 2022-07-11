
export function arrayBufferToHex (arrayBuffer,fmt = false) {
    if (typeof arrayBuffer !== 'object' || arrayBuffer === null || typeof arrayBuffer.byteLength !== 'number') {
      throw new TypeError('Expected input to be an ArrayBuffer')
    }
  
    var view = new Uint8Array(arrayBuffer)
    var result = ''
    var value
  
    for (var i = 0; i < view.length; i++) {
      value = view[i].toString(16)
      result += (value.length === 1 ? '0' + value : value)
      if (fmt){
        if (i < (view.length-1)){
          result += ":"
        }
      }
    }
    return result
}
  
export function hex_decode(string) {
    let bytes = [];
    string.replace(/../g, function (pair) {
        bytes.push(parseInt(pair, 16));
    });
    return new Uint8Array(bytes).buffer;
}

/*
Convert an ArrayBuffer into a string
from https://developer.chrome.com/blog/how-to-convert-arraybuffer-to-and-from-string/
*/
export function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}
  
export function zeroPad(num, places){
    return String(num).padStart(places, '0');
}