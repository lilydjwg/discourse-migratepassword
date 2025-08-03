# name: discourse-migratepassword
# about: enable alternative password hashes
# version: 0.11.4
# authors: Communiteq
# url: https://github.com/discoursehosting/discourse-migratepassword

# Usage:
# When migrating, store a custom field with the user containing the crypted password

# for vBulletin this should be #{password}:#{salt}      md5(md5(pass) + salt)
# for vBulletin5               #{token}                 bcrypt(md5(pass))
# for Phorum                   #{password}              md5(pass)
# for Wordpress                #{password}              phpass(8).crypt(pass)
# for SMF                      #{username}:#{password}  sha1(user+pass)
# for IPB                      #{salt}:#{hash}          md5(md5(salt)+md5(pass))
# for WBBlite                  #{salt}:#{hash}          sha1(salt+sha1(salt+sha1(pass)))
# for Joomla                   #{hash}:#{salt}          md5(pass+salt)
# for Joomla 3.2               #{password}              bcrypt(pass)
# for Question2Answer          #{salt}:#{passcheck}     sha1 (left(salt,8) + pass + right(salt,8))
# for Drupal 7                 #{password}              sha512(sha512(salt + pass) + pass) x iterations from salt.

#This will be applied at runtime, as authentication is attempted.  It does not apply at migration time.


enabled_site_setting :migratepassword_enabled

require 'digest'

after_initialize do

    module ::AlternativePassword
        def confirm_password?(password)
            return true if super
            return false unless SiteSetting.migratepassword_enabled
            return false unless self.custom_fields.has_key?('import_pass')

            if AlternativePassword::check_all(password, self.custom_fields['import_pass'])
                self.password = password
                self.custom_fields.delete('import_pass')

                if SiteSetting.migratepassword_allow_insecure_passwords
                    return save(validate: false)
                else
                    return save
                end
            end
            false
        end

        def self.check_all(password, crypted_pass)
            AlternativePassword::check_sha1(password, crypted_pass)
        end


        def self.check_sha1(password, crypted_pass)
            crypted_pass == Digest::SHA1.hexdigest(password)
        end
    end

    class ::User
        prepend AlternativePassword
    end

end
