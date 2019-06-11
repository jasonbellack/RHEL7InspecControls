control "xccdf_mil.disa.stig_rule_SV-86523r4_rule" do
  title "The Red Hat Enterprise Linux operating system must initiate a session lock for the screensaver after a period of inactivity for graphical user interfaces."
  desc  "
    Vulnerability Discussion: A session time-out lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not log out because of the temporary nature of the absence. Rather than relying on the user to manually lock their operating system session prior to vacating the vicinity, operating systems need to be able to identify when a user's session has idled and take action to initiate the session lock.
    
    The session lock is implemented at the point where session activity can be determined and/or controlled.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("dconf").installed? }
  describe file("/etc/dconf/profile/user") do
    its("content") { should match(/^user-db:user\nsystem-db:local$/) }
  end
  files = command("find /etc/dconf/db/ -type f -maxdepth 2 -regex .\\*/\\^\\[0-9\\].\\*\\$").stdout.split
  describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\[org\/gnome\/desktop\/screensaver\]([^\n]*\n+)+?idle-activation-enabled\s*=\s*true\s*$/m } do
    it { should_not be_empty }
  end
end
