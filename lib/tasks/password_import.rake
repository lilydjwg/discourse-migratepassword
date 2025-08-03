require 'csv'

namespace :migratepassword do
  desc "Import passwords from a CSV file"
  task :import, [:csv_file] => [:environment] do |_, args|
    abort "Please specify the CSV file to import" if args[:csv_file].blank?

    content = File.open(args[:csv_file]).read.sub("\xEF\xBB\xBF".force_encoding("UTF-8"), "")
    CSV.parse(content, headers: true) do |new_user|
      user = User.find_by_email(new_user['user_email'])
      if not user
        puts "User with email address #{new_user['user_email']} doesn't exist"
        next
      end
      if user.id && new_user['import_pass']
        puts "Setting password for #{user.username}"
        user.custom_fields['import_pass'] = new_user['import_pass'] 
        user.save_custom_fields(true)
      end
    end
  end
end
