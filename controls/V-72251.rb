control "xccdf_mil.disa.stig_rule_SV-86875r4_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that the SSH daemon is configured to only use the SSHv2 protocol."
  desc  "
    Vulnerability Discussion: SSHv1 is an insecure implementation of the SSH protocol and has many well-known vulnerability exploits. Exploits of the SSH daemon could provide immediate root access to the system.
    
    Satisfies: SRG-OS-000074-GPOS-00042, SRG-OS-000480-GPOS-00227
    
    Documentable: false
    
  "
  impact 1.0
  only_if { package("openssh-server").installed? }
  describe.one do
    describe sshd_config("/etc/ssh/sshd_config") do
      its('version') { should be >= '7.4' }
    end
    describe sshd_config("/etc/ssh/sshd_config") do
      its('protocol') { should cmp 2 }
    end
  end
end
