from bits import *
from constant_generator import *
from datetime import *
from hashlib import sha256
    
def ch(x,y,z):
    return (x & y) ^ (~x & z)
def maj(x,y,z):
    return (x & y) ^ (x & z) ^ (y & z)
def bigSigma0(x):
    return ((rotr(x,2) ^ rotr(x,13) ^ rotr(x,22)))
def bigSigma1(x):
    return ((rotr(x,6) ^ rotr(x,11) ^ rotr(x,25)))
def littleSigma0(x):
    return ((rotr(x,7) ^ rotr(x,18) ^ shr(x,3)))
def littleSigma1(x):
    return ((rotr(x,17) ^ rotr(x,19) ^ shr(x,10)))
def rotr(x,y):
    return (x >> y ) | (x << 32 - y)
def shr(x,y):
    return (x & 0xffffffff) >> y

def generateReport(input_message='abc'):
    '''Takes an input string which is hashed using SHA256. While the algorithm executes
    a dynamic report file is created which containes details about important values and varibles
    throughout the execution along with the message digest and comparison result to haslib sha256 implementation.
    Returns a string representation of the digest.'''
    now = datetime.now()
    #file_seconds = str((now.hour*(60**2)+now.minute*60 + now.second))                                                  # Can be used to generate a more dynamic report name
    if len(input_message) > 20:                                                                                         # Prevent OS file name length errors
        file_name = now.strftime("%m-%d-%y" + '__' + input_message[0:20] + '_' +str(len(input_message)*8)+'bits.txt')
    else:
        file_name = now.strftime("%m-%d-%y" + '__' + input_message +'.txt')
    
    # Initialize hash_values and kConstants
    hash_values = initHashValues()
    kConstants = initkConstants()
    
    
    # Set initial and working hash variables
    a = H0 = int(hash_values[0],16)
    b = H1 = int(hash_values[1],16)
    c = H2 = int(hash_values[2],16)
    d = H3 = int(hash_values[3],16)
    e = H4 = int(hash_values[4],16)
    f = H5 = int(hash_values[5],16)
    g = H6 = int(hash_values[6],16)
    h = H7 = int(hash_values[7],16)
    
    with open('reportPySHA256\\reports\\' + file_name, "w") as report:
        
        # Write Header To Report File
        report.write('SHA256 REPORT: ' + file_name[:-4] + '  {' + input_message + '}' + '\n')
        for i in range(len(file_name)+10):
            report.write('-')  
        report.write('\n')
        
        # Write Input Message To Report File
        report.write('\nInput Message:                  ' + input_message + '\n')

        # Padding The Message
        block = []
        binaryBuffer = getEightBit(input_message)
        
        # Copy The Input Message To The Message Block In 8-bit Binary Format
        i=0
        for x in binaryBuffer:                                  
            block.extend(splitBits(binaryBuffer[i]))
            i += 1 
        del binaryBuffer
        
        
        # Get input_message Block Size And Write To Report File. Then append final bit to block.
        l = len(block)
        report.write('  |---> Message Size:           ' + str(l) + ' bits' + '\n')
        block.append('1')
        
        # Calculate k-bits needed to pad message block and ensure it is divisible by 512. Write equation results and current block size plus k-bits to Report File
        k = (448-(l+1)) % 512                                                        
        report.write('  |---> (448-(l+1))%512 = k:    ' + str(k) + ' bits' + '\n')
        for x in range(k):                                      
            block.append('0')
        report.write('  |---> Block + k:              ' + str(len(block)) + ' bits' + '\n')
        
        # Append Final 64bits Containing input_messages block size. Write the final size in bits of the padded block to Report File
        i=0
        binaryBuffer = getSixtyFourBit(len(input_message*8))
        for x in binaryBuffer:
            block.extend(splitBits(binaryBuffer[i]))            
            i += 1
        del binaryBuffer
        report.write('  |---> Padded Block:           ' + str(len(block)) + ' bits' + '\n')
        
        # Write Initial Hash Values To Report File
        report.write('\nInitial Hash Values:  \n')
        for i in range(len(hash_values)):
            report.write('  |---> H' + str(i) + ':  ' + str(hash_values[i])[2:] + '\n')
        # Write K-Constants To Report File    
        report.write('\nK-Constants:  \n')
        for i in range(len(kConstants)):
            if i+1 != len(kConstants):
                report.write(str(hex(kConstants[i])[2:] + ', '))
            else:
                report.write(str(hex(kConstants[i])[2:]))
            if (i+1) % 8 == 0:
                report.write('\n')
        # Parsing The Message
        # Seperate input_message block into 16 32-bit strings and combine each character.
        seperatedBlock = [block[i:i+32] for i in range(0,len(block), 32)]
        parsedBlock = []
        W=[]
        for list in seperatedBlock:
            binaryString = int(''.join(str(digit) for digit in list),2)
            parsedBlock.append(int(binaryString))   
        if ((len(parsedBlock)%16) != 0):
            parsedBlock.clear()
        else:
            N = int(len(parsedBlock) / 16)                                      # Number Of 512-bit Blocks To Be Hashed.
            n = 16                                                              # Number Of 32-bit Words Each Block Contains.
            W = [parsedBlock[i:i + n] for i in range(0,len(parsedBlock),n)]     # Contains Individual 512-bit Blocks. Composed of 16 32-bit words.
            
            
        # Write The Entire Parsed input_message And The Number Of Blocks To Be Processed
        report.write('\nparsedBlock Content:'   + '\n')
        report.write('  |---> Number of Blocks: ' + str(N) + '\n')
        for i in range(len(parsedBlock)):
            report.write('  |---> parsedBlock[' + str(i) + ']  = '+ format(parsedBlock[i], '08x') + '\n')
            
        # Initialize The First 512-bit Block In The Message Schedule To Be Processed and Write It To The Report File
        schedule = W.pop(0)
        for i in range(len(schedule)):
            report.write('      |---> Message Schedule[' + str(i) + ']  = '+ format(schedule[i], '08x') + '\n')
            
        # Begin Processing Message Blocks
        while len(schedule) != 0:
            for word in schedule:
                for t in range(16,64):
                    expression = (  (littleSigma1(schedule[t-2])) + 
                                    (schedule[t-7]) +
                                    littleSigma0(schedule[t-15]) +
                                    schedule[t-16]
                                )
                    schedule.append(expression & 0xffffffff)
                # Eight Working Variables Set To Current Hash Variables
                a = H0
                b = H1
                c = H2
                d = H3
                e = H4
                f = H5
                g = H6
                h = H7
                # Write Header For Working Variables
                report.write('\n                  a   ' +
                             '       b   '+'       c   '+
                             '       d   '+'       e   '+
                             '       f   '+'       g   '+
                             '       h   \n')
                for _t in range (64):
                    T2 = ((bigSigma0(a) + maj(a,b,c)) % (2**32))
                    T1 = ((h + bigSigma1(e)+ch(e,f,g) + kConstants[_t] + schedule[_t]) % (2**32))
                    h = g
                    g = f
                    f = e
                    e = ((d + T1) % (2**32))
                    d = c
                    c = b
                    b = a
                    a = ((T1 + T2) % (2**32))
                    # Write Intermediate Hash Values To Report File
                    if _t + 1 == 64:
                        report.write('      _t=' + str(_t) + ':   ' + str(format(a,'08x')  + '   ' + str(format(b,'08x') + '   ' +str(format(c,'08x')) + '   '  +  str(format(d,'08x') + '   ' + str(format(e,'08x')) + '   ' + str(format(f,'08x')) + '   ' + str(format(g,'08x')) + '   ' + str(format(h,'08x')) + '\n\n'))))
                    else:
                        report.write('      _t=' + str(_t) + ':   ' + str(format(a,'08x')  + '   ' + str(format(b,'08x') + '   ' +str(format(c,'08x')) + '   '  +  str(format(d,'08x') + '   ' + str(format(e,'08x')) + '   ' + str(format(f,'08x')) + '   ' + str(format(g,'08x')) + '   ' + str(format(h,'08x')) + '\n'))))
            
                current_variable = [H0, H1, H2, H3, H4, H5, H6, H7]
                H0 = (a + H0) % (2**32)
                H1 = (b + H1) % (2**32)
                H2 = (c + H2) % (2**32)
                H3 = (d + H3) % (2**32)
                H4 = (e + H4) % (2**32)
                H5 = (f + H5) % (2**32)
                H6 = (g + H6) % (2**32)
                H7 = (h + H7) % (2**32)
                report.write(
                'H' + '0: ' + format(current_variable[0],'08x') + ' + ' + str(format(a,'08x')) + ' = ' + str(format(H0,'08x')) + '\n' + 
                'H' + '1: ' + format(current_variable[1],'08x') + ' + ' + str(format(b,'08x')) + ' = ' + str(format(H1,'08x')) + '\n' +
                'H' + '2: ' + format(current_variable[2],'08x') + ' + ' + str(format(c,'08x')) + ' = ' + str(format(H2,'08x')) + '\n' +
                'H' + '3: ' + format(current_variable[3],'08x') + ' + ' + str(format(d,'08x')) + ' = ' + str(format(H3,'08x')) + '\n' +
                'H' + '4: ' + format(current_variable[4],'08x') + ' + ' + str(format(e,'08x')) + ' = ' + str(format(H4,'08x')) + '\n' +
                'H' + '5: ' + format(current_variable[5],'08x') + ' + ' + str(format(f,'08x')) + ' = ' + str(format(H5,'08x')) + '\n' +
                'H' + '6: ' + format(current_variable[6],'08x') + ' + ' + str(format(g,'08x')) + ' = ' + str(format(H6,'08x')) + '\n' +
                'H' + '7: ' + format(current_variable[7],'08x') + ' + ' + str(format(h,'08x')) + ' = ' + str(format(H7,'08x')) + '\n\n' 
                )
                
                
                # Clear Current Content Of schedule And Ensure There's Another Block To Be Hashed.
                # If So, The Next Block Is Added To The Schedule Where It Is Hashed.
                # If Not, The Final Digest Is Composed, Tested Against The hashlib Digest, Written To The Report File, And Returned
                schedule.clear()
                if len(W) > 0:
                    schedule = W.pop(0)
                    for i in range(len(schedule)):
                        report.write('      |---> Message Schedule[' + str(i) + ']  = '+ format(schedule[i], '08x') + '\n')
                else:
                    digest = (
                        str(format(H0,'08x'))+
                        str(format(H1,'08x'))+
                        str(format(H2,'08x'))+
                        str(format(H3,'08x'))+
                        str(format(H4,'08x'))+
                        str(format(H5,'08x'))+
                        str(format(H6,'08x'))+
                        str(format(H7,'08x'))
                        )
                    proven_digest = sha256(input_message.encode('utf-8')).hexdigest()
                    report.write('Generated Digest: '  + digest + '\n' + 'hashlib Digest:   ' + proven_digest + '\n\n')
                    if digest.lower() == proven_digest.lower():
                        report.write('PASSED: DIGESTS ARE EQUAL')
                    else:
                        report.write('FAILED: DIGESTS ARE NOT EQUAL')
                    return digest
                    
        
     

    
#generateReport(input("Enter an Input Message: "))
generateReport('abc')
generateReport('abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')
generateReport('abcdbcdecdefdefgefghxczxczxczcxzxczxczxczxcfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq')