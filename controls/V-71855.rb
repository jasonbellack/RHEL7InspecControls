# encoding: UTF-8

control "xccdf_mil.disa.stig_rule_SV-86479r3_rule" do
    title "The Red Hat Enterprise Linux operating system must be configured so that the cryptographic hash of system files and commands matches vendor values."
    desc  "
      Vulnerability Discussion: Without cryptographic integrity protections, system command and files can be altered by unauthorized users without detection.
      
      Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions using asymmetric cryptography enabling distribution of the public key to verify the hash information while maintaining the confidentiality of the key used to generate the hash.
      
      Documentable: false
      
    "
    impact 1.0
    describe command("rpm -Va | grep '^..5'") do
      its('stdout') { should eq '' }
      its('stderr') { should eq '' }
      its('exit_status') { should eq 0 }
    end
  end
