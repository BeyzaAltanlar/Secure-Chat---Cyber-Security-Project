# Secure-Chat---Cyber-Security-Project

SECURE CHAT APP
Amaç : Siber güvenlik dersinde gördüğümüz özellikleri kullanarak, kullanıcıların
konuşabileceği güvenli bir chat uygulaması yapmak.
Proje içeriği ve Genel Taslak
Bu projenin içerdikleri :
1. Kimlik Doğrulama
2. Anahtar Yönetimi
3. Simetrik ve Asimetrik şifrelemenin beraber kullanımı
4. Salting
5. Mesaj İmzalama
   
Eklemeyi düşündüklerim:
Saldırı Tespit


1. Kimlik Doğrulama
Kullanıcı Kaydı Oluşturma (register_user fonksiyonu):
Kullanıcı, kullanıcı adı ve şifresiyle birlikte sisteme kayıt olur.
Parola, güvenli hale getirilmesi için tuzlanır (salting) ve tuzlanmış parola, tuz ile birlikte
dosyaya kaydedilir.
Simetrik ve asimetrik anahtar çiftleri oluşturulur, özel anahtar şifrelenir ve güvenli bir şekilde
dosyaya kaydedilir.
Kullanıcının tuzu da dosyaya kaydedilir.
Kullanıcı Kimlik Doğrulama (authenticate_user fonksiyonu):
Kullanıcı, kullanıcı adı ve şifresiyle giriş yapmaya çalışır.
Girilen kullanıcı adı ve şifre, dosyadaki kayıtlarla karşılaştırılır.
Tuz kullanılarak girilen şifre ile kaydedilmiş şifre karşılaştırılır. Eğer eşleşirse, kimlik
doğrulama başarılı kabul edilir.

2.Anahtar Yönetimi
Mesaj içeriği, AES (Advanced Encryption Standard) simetrik şifreleme algoritması ile
şifrelenir. Anahtar oluşturulurken os.urandom(32) kullanılarak rastgele bir 256-bit (32 byte)
anahtar elde edilir. Anahtarın güvenli bir şekilde iletilmesi için RSA asimetrik şifreleme
algoritması kullanılır. Özel anahtar (private key) ve genel anahtar (public key) çifti,
generate_key fonksiyonu ile oluşturulur.
Anahtar üretme için (derive_key fonksiyonu), kullanıcının parolası ve tuzu kullanarak bir
üretilmiş anahtar oluşturur (PBKDF2 algoritması kullanılır). Bu türetilmiş anahtar, simetrik
anahtarı şifrelemek ve çözmek için kullanılır.
Anahtarların güvenli iletimi :
Simetrik anahtarın güvenli bir şekilde iletilmesi için, bu anahtar RSA asimetrik şifreleme
algoritması kullanılarak şifrelenir. Bu işlemde, özel anahtar ile şifrelenen simetrik anahtar,
sadece karşı tarafın genel anahtarı ile çözülebilir. Bu yöntem, anahtarın güvenli bir şekilde
iletilmesini sağlar.

3.Simetrik ve Asimetrik Şifrelemenin Beraber Kullanımı
Simetrik şifreleme (AES) ve asimetrik şifreleme (RSA) algoritmaları bir arada kullanılarak
güvenli bir iletişim sağlanmaktadır. Simetrik şifreleme, verilerin hızlı bir şekilde şifrelenip
çözülmesine olanak tanırken, asimetrik şifreleme ise anahtar değişimini güvenli bir şekilde
gerçekleştirmeye olanak tanır. Güvenliliği artırmak için ikisi de kullanıldı

4. Salting
Projede Parola güvenliği için salting yöntemi de ek olarak kullanılmıştır. Parola türetme
işlemleri sırasında salting, kötü niyetli kişilerin önceden hesaplanmış "rainbow table"
(gökkuşağı tablosu) saldırılarına karşı direnç sağlar. Rainbow table saldırıları, önceden
hesaplanmış parola-hash çiftlerinin depolandığı tablolardan yararlanarak hızlı bir şekilde
parolaların çözülmesini hedefler.
Her kullanıcının tuzu farklıdır, bu da her kullanıcının parola türetme işleminden geçirildiğinde
farklı bir türetilmiş anahtara sahip olacağı anlamına gelir. Salting kullanarak, projedeki parola
güvenliğinin artırılması hedeflenmiştir. Bu kombinasyon, yüksek güvenlik düzeyi ve hızlı veri
iletimi sağladı.

5. Mesaj İmzalama
Mesaj imzalama işlemi, mesajın gönderen tarafından doğrulandığını garantiler. Projede, özel
anahtar kullanılarak mesajlar imzalanır ve alıcı tarafında bu imza, gönderenin kimliğini
doğrulamak için kullanılır. Bu, mesaj bütünlüğünü sağlamak ve mesajın doğruluğunu
doğrulamak için yapılmıştır. İmza doğrulama işlemi sırasında,
cryptography.hazmat.primitives.asymmetric.padding.PSS (Probabilistic Signature
Scheme) kullanılarak padding (dolgu) sağlanmıştır. Mesajın orijinal olduğunun kanıtıdır.
Yukarıdaki güvenliklere ek olarak kimlik doğrulama, bütünlük ve güvenlik dijital imza ile de
hedeflenmiştir.
Sonuç
Bu proje, siber güvenlik konseptlerini pratiğe dökme amacıyla geliştirildi. Güçlü şifreleme
algoritmalarının doğru bir şekilde kullanılması, kullanıcı kimlik doğrulama süreçleri ve
anahtar yönetimi prensipleri uygulanmaya ve güvenli bir uygulama geliştirmeye çalışıldı. 
