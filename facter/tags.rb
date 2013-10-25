# Peter Shipley <peter.shipley at gmail>
#
# anyone is  free to use this, if you improve it, send me a patch
#

require 'facter'
 
if (File.exist?("/usr/bin/aws")) and File.exist?("/etc/puppet/awssecret") and (id = Facter['ec2_instance_id'].value)
    cmd = "/usr/bin/aws --secrets-file=/etc/puppet/awssecret --simple describe-tags --filter resource-id=#{id}"
    # print("Read fact cmd #{cmd}\n")
    Facter::Util::Resolution.exec(cmd).split(/\n/).collect do |line|
	# print("Read fact #{line}\n")
	if !line.nil?
	    data = line.split(/\s+/)
	    if data[2] =~ /^\w+$/i
		# print("Recording fact #{data[2]} = #{data[3]}\n")
		Facter.add("tag_#{data[2].downcase}") do
		    setcode { data[3..100].join(' ') }
		end
	    else
		print("facter tag.rb bad tag key \"#{data[2]}\"\n")
	    end
	end
    end
else
    print("facter tag.rb not run\n")
end

