control "xccdf_mil.disa.stig_rule_SV-92521r2_rule" do
  title "The Red Hat Enterprise Linux operating system must implement virtual address space randomization."
  desc  "
    Vulnerability Discussion: Address space layout randomization (ASLR) makes it more difficult for an attacker to predict the location of attack code he or she has introduced into a process's address space during an attempt at exploitation. Additionally, ASLR also makes it more difficult for an attacker to know the location of existing code in order to repurpose it using return-oriented programming (ROP) techniques.
    
    Documentable: false
    
  "
  impact 0.5
  describe.one do
    files = command("find /etc/sysctl.conf -type -f").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^kernel\.randomize_va_space[\s]=[\s]2.*$/ } do
      it { should_not be_empty }
    end
    describe file("/etc/sysctl.conf") do
      its("content") { should match(/^kernel\.randomize_va_space[\s]=[\s]2.*$/) }
    end
  end
end
