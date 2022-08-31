def getEightBit( inString : str) : 
    eightBit = []
    for c in inString:
        eightBit.append(''.join(format(ord(c), '08b')))
    return eightBit

def getSixteenBit ( inString : str ):
    sixteenBit = []
    for c in inString:
        sixteenBit.append(''.join(format(ord(c),'016b')))
    return sixteenBit

def getThirtyTwoBit ( inString : str) :
    thirtyTwoBit = []
    for c in inString:
        thirtyTwoBit.append(''.join(format(ord(c), '032b')))
    return thirtyTwoBit

def getSixtyFourBit ( inString : str) :
    sixtyFourBit = []
    for c in inString:
        sixtyFourBit.append(''.join(format(ord(c), '064b')))
    return sixtyFourBit

def getSixtyFourBit ( inInt : int):
    sixtyFourBit = []
    sixtyFourBit.append(''.join(format(inInt, '064b')))
    return sixtyFourBit

def splitBits( inBits : str):
    return [c for c in inBits]