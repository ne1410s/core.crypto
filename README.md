# @ne1410s/crypto

ES Crypto Utilities

## Important for Windows Users:

`node-webcrypto-ossl` brings in a workable crypto implementation for client and server side js. It is built from source (with node-gyp) when the package is installed. Normally, one might install tools for this, such as `npm i -g windows-build-tools`.

**However**, this did not seem to provide a reliable solution in all cases. So it is recommended to install the following components manually instead:

- Python 2.7.x
- Visual Studio 2019, with:
  - MSVC v142 - VS 2019 C++ build tools (v14.28)
  - Windows 10 SDK (10.0.17763.0)
