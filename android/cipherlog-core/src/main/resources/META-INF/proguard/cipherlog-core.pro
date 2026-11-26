# R8 rules shipped inside the cipherlog-core jar (R8 reads META-INF/proguard/*.pro from every jar), so they apply to an
# app that depends on cipherlog-core directly as well as through the cipherlog AAR. cipherlog itself needs no keep
# rules: nothing of it is reached by reflection.

# Tink 1.24.0 refers to android.crypto.hpke.* (newer Android platforms only, used by Tink only where the platform has
# them). Those classes are not in the compileSdk 36 android.jar, and R8 stops a release build on a missing class.
-dontwarn android.crypto.hpke.**

# An app that excludes Tink: cipherlog's Crypto class names Tink types directly. With this rule the minified build
# succeeds and the documented fallback happens at run time (the writer turns itself off: "cipherlog off: crypto
# unavailable"), instead of a failed build.
-dontwarn com.google.crypto.tink.**
