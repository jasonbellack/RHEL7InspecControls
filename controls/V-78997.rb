control "xccdf_mil.disa.stig_rule_SV-93703r2_rule" do
  title "The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver idle-activation-enabled setting for the graphical user interface."
  desc  "
    Vulnerability Discussion: A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.
    
    The session lock is implemented at the point where session activity can be determined.
    
    The ability to enable/disable a session lock is given to the user by default. Disabling the user's ability to disengage the graphical user interface session lock provides the assurance that all sessions will lock after the specified period of time.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("dconf").installed? }
  
  dconf_dirs = command("find /etc/dconf/db/ -type d -maxdepth 1").stdout.split
  dconf_dirs_files = command("find #{dconf_dirs} -type f -maxdepth 1 -regex \\^\\[0-9\\].\\*\\$").stdout.split
  dconf_setting_in_file = dconf_dirs_files.delete_if { |f| file(f).content !~ /^\[org\/gnome\/desktop\/screensaver\]([^\n]*\n+)+?idle-activation-enabled\s*=\s*(?:true|false)\s*$/ }
  
  describe dconf_setting_in_file do
    it { should_not be_empty }
  end
  
  dconf_lock_paths = dconf_setting_in_file.map { |f| File.dirname(f) + "/locks" }
  lock_files = command("find #{dconf_lock_paths.join(' ')} -maxdepth 1 -regex \\^.\\*\\$").stdout.split
  lock_files_with_setting = lock_files.delete_if { |f| file(f).content !~ /^\[org\/gnome\/desktop\/screensaver\]([^\n]*\n+)+?idle-activation-enabled\s*=\s*(?:true|false)\s*$/ }
  
  describe lock_files_with_setting do
    it { should_not be_empty }
  end
  
  matching_setting_dirs = dconf_setting_in_file.map { |f| File.dirname(f) }
  matching_lock_file_dirs = lock_files_with_setting.map { |f| File.dirname(f).gsub("/locks", "") }
  describe matching_setting_dirs.sort == matching_lock_file_dirs.sort do
    it { should eq true }
  end
end
