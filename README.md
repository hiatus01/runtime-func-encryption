# runtime-func-encryption
![sample](https://cdn.discordapp.com/attachments/1215137187209814036/1349229167937585255/Annotation_2025-03-11_205438.png?ex=67d25715&is=67d10595&hm=d6f3c1cc0521b3d0d28337c1a63bb1d57108b5e54774949f6499cf3b48fc862c&)

Encrypt your functions during runtime (ud method)

Works on MSVC.

This protects your code since the code for each function is completely encrypted. The attacker also won't be able to see which functions you are calling, provided you use proper string encryption, since the only call they will be able to see is `EncryptFunction` and `RunFunction`.

Have fun pasting, but give credit.
