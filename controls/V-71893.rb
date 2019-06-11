control "xccdf_mil.disa.stig_rule_SV-86517r5_rule" do
  title "The Red Hat Enterprise Linux operating system must initiate a screensaver after a 15-minute period of inactivity for graphical user interfaces."
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
  describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\[org\/gnome\/desktop\/session\](?:[^\n]*\n+)+?idle-delay\s*=\s*uint32[\s]+([0-9]*)/m } do
    it { should_not be_empty }
  end
  files.each do |f|
    file(f).content.to_s.scan(/^\[org\/gnome\/desktop\/session\](?:[^\n]*\n+)+?idle-delay\s*=\s*uint32[\s]+([0-9]*)/m).flatten.each do |entry|
      describe entry do
        it { should cmp <= 900 }
      end
    end
  end
end
