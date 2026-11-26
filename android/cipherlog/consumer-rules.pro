# The same rules as cipherlog-core's META-INF/proguard/cipherlog-core.pro (kept here too, so the AAR carries them even
# when a build tool ignores rules inside jars). cipherlog itself needs no keep rules: nothing of it is reached by
# reflection, and Tink ships its own keep rules.

# Tink 1.24.0 refers to android.crypto.hpke.* (newer Android platforms only, used by Tink only where the platform has
# them). Those classes are not in the compileSdk 36 android.jar, and R8 stops a release build on a missing class.
-dontwarn android.crypto.hpke.**

# An app that excludes Tink: with this rule the minified build succeeds and the writer turns itself off at run time
# ("cipherlog off: crypto unavailable"), as documented, instead of a failed build.
-dontwarn com.google.crypto.tink.**
