
// To check if a library is compiled with CocoaPods you
// can use the `COCOAPODS` macro definition which is
// defined in the xcconfigs so it is available in
// headers also when they are imported in the client
// project.


// ASCIImage
#define COCOAPODS_POD_AVAILABLE_ASCIImage
#define COCOAPODS_VERSION_MAJOR_ASCIImage 1
#define COCOAPODS_VERSION_MINOR_ASCIImage 0
#define COCOAPODS_VERSION_PATCH_ASCIImage 0

// lua
#define COCOAPODS_POD_AVAILABLE_lua
#define COCOAPODS_VERSION_MAJOR_lua 5
#define COCOAPODS_VERSION_MINOR_lua 3
#define COCOAPODS_VERSION_PATCH_lua 1

// Release build configuration
#ifdef RELEASE

  // Sparkle
  #define COCOAPODS_POD_AVAILABLE_Sparkle
  #define COCOAPODS_VERSION_MAJOR_Sparkle 1
  #define COCOAPODS_VERSION_MINOR_Sparkle 10
  #define COCOAPODS_VERSION_PATCH_Sparkle 0

#endif
