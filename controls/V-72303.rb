control "xccdf_mil.disa.stig_rule_SV-86927r4_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that remote X connections for interactive users are encrypted."
  desc  "
    Vulnerability Discussion: Open X displays allow an attacker to capture keystrokes and execute commands remotely.
    
    Documentable: false
    
  "
  impact 1.0
  describe.one do
    describe package("openssh-server") do
      it { should_not be_installed }
    end
    describe file("/etc/ssh/sshd_config") do
      its("content") { should match(/^[\s]*X11Forwarding[ \t]+([^\s#]*)[ \t]*(?:|(?:#.*))?$/mi) }
    end
    file("/etc/ssh/sshd_config").content.to_s.scan(/^[\s]*X11Forwarding[ \t]+([^\s#]*)[ \t]*(?:|(?:#.*))?$/mi).flatten.each do |entry|
      describe entry do
        it { should match(/^(yes|"yes")$/) }
      end
    end
  end
end
