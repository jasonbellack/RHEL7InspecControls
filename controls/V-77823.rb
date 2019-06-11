control "xccdf_mil.disa.stig_rule_SV-92519r2_rule" do
  title "The Red Hat Enterprise Linux operating system must require authentication upon booting into single-user and maintenance modes."
  desc  "
    Vulnerability Discussion: If the system does not require valid root authentication before it boots into single-user or maintenance mode, anyone who invokes single-user or maintenance mode is granted privileged access to all files on the system.
    
    Documentable: false
    
  "
  impact 0.5
  describe file("/usr/lib/systemd/system/rescue.service") do
    it { should exist }
    its("content") { should match(/^ExecStart=-\/bin\/sh[\s]-c[\s]\"\/usr\/sbin\/sulogin;[\s]\/usr\/bin\/systemctl[\s]--fail[\s]--no-block[\s]default\"$/) }
  end
  files = command("find /usr/lib/systemd/system/rescue.service -type f").stdout.split
  describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^ExecStart=-\/bin\/sh[\s]-c[\s]\"\/usr\/sbin\/sulogin;[\s]\/usr\/bin\/systemctl[\s]--fail[\s]--no-block[\s]default\"$/ } do
    it { should_not be_empty }
  end
end

