control "xccdf_mil.disa.stig_rule_SV-87807r4_rule" do
  title "The Red Hat Enterprise Linux operating system must prevent a user from overriding the screensaver lock-delay setting for the graphical user interface."
  desc  "
    Vulnerability Discussion: A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
    
    The session lock is implemented at the point where session activity can be determined and/or controlled.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("dconf").installed? }
  dconf_dirs = command("find /etc/dconf/db/ -type d -maxdepth 1").stdout.split
  dconf_dirs_files = dconf_dirs.map { |dir| command("find #{dir} -type f -maxdepth 1 | grep ^[0-9].*$").stdout.strip }
  dconf_setting_in_file = dconf_dirs_files.map { |f| command("grep -H ^\[org/gnome/desktop/screensaver\]([^\n]*\n+)+?lock-delay\s*=\s*uint32\s+[0-5]\s*$ #{f} | cut -d: -f1").stdout.strip }
  dconf_setting_in_file.reject! { |f| f.empty? }
  if dconf_setting_in_file.empty?
    describe dconf_setting_in_file do
      it { should be_empty }
    end
  else
    dconf_lock_paths = dconf_setting_in_file.map { |f| File.dirname(f) + "/locks" }
    lock_files = command("find #{dconf_lock_paths.join(' ')}").stdout.split
    lock_files_with_setting = lock_files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\/org\/gnome\/desktop\/screensaver\/lock-delay$/ }
    describe lock_files_with_setting do
      it { should_not be_empty }
    end
    matching_setting_dirs = dconf_setting_in_file.map { |f| File.dirname(f) }
    matching_lock_file_dirs = lock_files_with_setting.map { |f| File.dirname(f).gsub("/locks", "") }
    describe matching_setting_dirs.sort == matching_lock_file_dirs.sort do
      it { should eq true }
    end
  end
end
