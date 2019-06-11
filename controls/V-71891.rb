control "xccdf_mil.disa.stig_rule_SV-86515r5_rule" do
  title "The Red Hat Enterprise Linux operating system must enable a user session lock until that user re-establishes access using established identification and authentication procedures."
  desc  "
    Vulnerability Discussion: A session lock is a temporary action taken when a user stops work and moves away from the immediate physical vicinity of the information system but does not want to log out because of the temporary nature of the absence.
    
    The session lock is implemented at the point where session activity can be determined.
    
    Regardless of where the session lock is determined and implemented, once invoked, the session lock must remain in place until the user reauthenticates. No other activity aside from reauthentication must unlock the system.
    
    Satisfies: SRG-OS-000028-GPOS-00009, SRG-OS-000030-GPOS-00011
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("dconf").installed? }
  describe file("/etc/dconf/profile/user") do
    its("content") { should match(/^user-db:user\nsystem-db:local$/) }
  end
  files = command("find /etc/dconf/db/ -type f -maxdepth 2 -regex .\\*/\\^\\[0-9\\].\\*\\$").stdout.split
  describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^\[org\/gnome\/desktop\/screensaver\]([^\n]*\n+)+?lock-enabled\s*=\s*true\s*$/m } do
    it { should_not be_empty }
  end
end
