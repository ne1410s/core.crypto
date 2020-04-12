# ne14.crypto
ES Crypto Utilities

## Important for Windows Users:
`node-webcrypto-ossl` brings in a workable crypto implementation for client and server side js. It is built from source (with node-gyp) when the package is installed. Normally, one might install tools for this, such as `npm i -g windows-build-tools`.

**However**, this did not seem to provide a reliable solution in all cases. So it is recommended to install the following components manually instead: 
 - Python 2.7.x
 - Visual Studio 2013 or higher, with:
   - Cpp Build Tools
   - VC++ v1.40
   - Windows SDK
