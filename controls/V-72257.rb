control "xccdf_mil.disa.stig_rule_SV-86881r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the SSH private host key files have mode 0640 or less permissive."
  desc  "
    Vulnerability Discussion: If an unauthorized user obtains the private SSH host key file, the host could be impersonated.
    
    Documentable: false
    
  "
  impact 0.5
  only_if { package("openssh-server").installed? }
  files = command("find /etc/ssh -type f -maxdepth 1 -regex \^\.\*key\$").stdout.split
  files.each { |f|
    describe file(f) do
      it { should exist }
      it { should_not be_executable.by "group" }
      it { should_not be_readable.by "group" }
      it { should_not be_writable.by "group" }
      it { should_not be_executable.by "other" }
      it { should_not be_readable.by "other" }
      it { should_not be_writable.by "other" }
      it { should_not be_executable.by "owner" }
    end
  }
end
