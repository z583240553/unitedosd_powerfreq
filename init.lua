local _M = {}
local bit = require "bit"
local cjson = require "cjson.safe"
local Json = cjson.encode

local strload

--Json的Key，用于协议帧头的几个数据
local cmds = {
  [0] = "length",
  [1] = "DTU_time",
  [2] = "DTU_status",
  [3] = "DTU_function",
  [4] = "device_address"
}

--Json的Key，用于工频螺杆机数据  对应工频螺杆机云端显示表
local status_cmds = {
  [1] = "Runtime",
  [2] = "Loadruntime",
  [3] = "Systempress",
  [4] = "Exhaustpress",
  [5] = "Oilpress",
  [6] = "Systemtemp",
  [7] = "Exhausttemp",
  [8] = "Fbearingtemp",
  [9] = "Bbearingtemp",
  [10] = "Acurrent",
  [11] = "Bcurrent",
  [12] = "Ccurrent",
  [13] = "GreaseT",
  [14] = "LubeT",
  [15] = "OilgasseparatorT",
  [16] = "OilfilterT",
  [17] = "AirfilterT",
  [18] = "ExhaustpipeT",
  [19] = "MotorbearingT",
  [20] = "SafetyvalveT",
  [21] = "MinipressvalveT",
  [22] = "HostbladeT",
  [23] = "HostinsulationT",
  [24] = "HeadbearingT",
  [25] = "HeadsealT",
  [26] = "HeadgearT",
  [27] = "FanbearingT",
  [28] = "FanbladeT",
  [29] = "MaincontactorN",
  [30] = "StarcontactorN",
  [31] = "AnglecontactorN",
  [32] = "AirloadvalveN",
  [33] = "AirsolenoidvalveN",
  [34] = "FancontactorN",
  [35] = "Inletpress"
}
--Json的Key，用于工频螺杆机运行状态1数据  对应工频螺杆机云端显示表
local status1_bit_cmds = {
  [1] = "RunState1_01",
  [2] = "RunState1_02",
  [3] = "RunState1_03",
  [4] = "RunState1_04",
  [5] = "RunState1_05",
  [6] = "RunState1_06",
  [7] = "RunState1_07",
  [8] = "RunState1_08",
  [9] = "RunState1_09",
  [10] = "RunState1_10",
  [11] = "RunState1_11",
  [12] = "RunState1_12",
  [13] = "RunState1_13"
}
--Json的Key，用于工频螺杆机运行状态2数据  对应工频螺杆机云端显示表
local status2_bit_cmds = {
  [1] = "RunState2_01",
  [2] = "RunState2_02",
  [3] = "RunState2_03",
  [4] = "RunState2_04",
  [5] = "RunState2_05",
  [6] = "RunState2_06",
  [7] = "RunState2_07",
  [8] = "RunState2_08",
  [9] = "RunState2_09",
  [10] = "RunState2_10"
}
--Json的Key，用于工频螺杆机运行状态3数据  对应工频螺杆机云端显示表
local status3_bit_cmds = {
  [1] = "RunState3_01",
  [2] = "RunState3_02",
  [3] = "RunState3_03",
  [4] = "RunState3_04",
  [5] = "RunState3_05",
  [6] = "RunState3_06",
  [7] = "RunState3_07",
  [8] = "RunState3_08",
  [9] = "RunState3_09",
  [10] = "RunState3_10",
  [11] = "RunState3_11",
  [12] = "RunState3_12",
  [13] = "RunState3_13",
  [14] = "RunState3_14",
  [15] = "RunState3_15",
  [16] = "RunState3_16"
}
--Json的Key，用于工频螺杆机运行状态4数据  对应工频螺杆机云端显示表
local status4_bit_cmds = {
  [1] = "RunState4_01",
  [2] = "RunState4_02",
  [3] = "RunState4_03",
  [4] = "RunState4_04",
  [5] = "RunState4_05",
  [6] = "RunState4_06",
  [7] = "RunState4_07",
  [8] = "RunState4_08",
  [9] = "RunState4_09",
  [10] = "RunState4_10",
  [11] = "RunState4_11",
  [12] = "RunState4_12",
}

--FCS校验
function utilCalcFCS( pBuf , len )
  local rtrn = 0
  local l = len

  while (len ~= 0)
    do
    len = len - 1
    rtrn = bit.bxor( rtrn , pBuf[l-len] )
  end

  return rtrn
end

--将字符转换为数字
function getnumber( index )
   return string.byte(strload,index)
end

--编码 /in 频道的数据包
function _M.encode(payload)
  return payload
end

--解码 /out 频道的数据包
function _M.decode(payload)
	local packet = {['status']='not'}
		
	--FCS校验的数组(table)，用于逐个存储每个Byte的数值
	local FCS_Array = {}

	--用来直接读取发来的数值，并进行校验
	local FCS_Value = 0

	--strload是全局变量，唯一的作用是在getnumber函数中使用
	strload = payload

	--前2个Byte是帧头，正常情况应该为';'和'1'
	local head1 = getnumber(1)
	local head2 = getnumber(2)
	
	--当帧头符合，才进行其他位的解码工作
	if ( (head1 == 0x3B) and (head2 == 0x31) ) then

		--数据长度
		local templen = bit.lshift( getnumber(3) , 8 ) + getnumber(4)

		FCS_Value = bit.lshift( getnumber(templen+5) , 8 ) + getnumber(templen+6)

		--将全部需要进行FCS校验的Byte写入FCS_Array这个table中
		for i=1,templen+4,1 do
			table.insert(FCS_Array,getnumber(i))
		end

		--进行FCS校验，如果计算值与读取指相等，则此包数据有效；否则弃之
		if(utilCalcFCS(FCS_Array,#FCS_Array) == FCS_Value) then
			packet['status'] = 'SUCCESS'
		else
			packet = {}
			packet['status'] = 'FCS-ERROR'
			return Json(packet)
		end

		--[[--数据长度
		packet[ cmds[0] ] = templen
		]]
		--运行时长
		packet[ cmds[1] ] = bit.lshift( getnumber(5) , 24 ) + bit.lshift( getnumber(6) , 16 ) + bit.lshift( getnumber(7) , 8 ) + getnumber(8)
		--[[--采集模式
		local mode = getnumber(9)
		if mode == 1 then
			packet[ cmds[2] ] = 'Mode-485'
			else
			packet[ cmds[2] ] = 'Mode-232'
		end
		]]
		--func为判断是 实时数据/参数/故障 的参数
		local func = getnumber(10)
		if func == 1 then  --解析状态数据
			packet[ cmds[3] ] = 'func-status'
			--[[--设备modbus地址
			packet[ cmds[4] ] = getnumber(11)
			]]

			local databuff_table={} --用来暂存上传的实际数据
			local bitbuff_table={}  --用来暂存运行状态1/2/3/4的每位bit值

			--依次读入上传的数据
			for i=1,(templen-7-8)/2,1 do
				databuff_table[i] = bit.lshift( getnumber(10+i*2) , 8 ) + getnumber(11+i*2)
			end

			--将上传的数据转化为JSON格式数据 根据协议将上传的数据进行格式处理
			packet[ status_cmds[1] ] = databuff_table[2]*65536+databuff_table[1]
			packet[ status_cmds[2] ] = databuff_table[4]*65536+databuff_table[3]
			--压力组
			for i=1,3,1 do
				local x = bit.band(databuff_table[4+i],bit.lshift(1,15))
				if(x == 0) then
					packet[ status_cmds[2+i] ] = databuff_table[4+i]/10                  --正压力
				else 
					packet[ status_cmds[2+i] ] = -((0xffff-databuff_table[4+i]+1)/10)    --负压力
				end    
			end

			--温度组
			for i=1,4,1 do
				local x = bit.band(databuff_table[7+i],bit.lshift(1,15))
				if(x == 0) then
					packet[ status_cmds[5+i] ] = databuff_table[7+i]                 --正温度
				else
					packet[ status_cmds[5+i] ] = -(0xffff-databuff_table[7+i]+1)     --负温度      
			end
	
			--电流+时间组
			for i=1,19,1 do
				packet[ status_cmds[9+i] ] = databuff_table[11+i]         
			end

			--运行次数组
			for i=1,6,1 do
				packet[ status_cmds[28+i] ] = databuff_table[30+i]*10     
			end

			--最后添加的进气压力
			if(bit.band(getnumber(92),bit.lshift(1,7) == 0) then                
				packet[ status_cmds[35] ] =(bit.lshift(getnumber(92),8) + getnumber(93)) /10   --正压力
			else
				local m = bit.lshift(getnumber(92),8) + getnumber(93)
				packet[ status_cmds[35] ] = -((0xffff-m+1)/10)                                 --负压力
			end
			
			--解析运行状态1(高字节对应getnumber[84],低字节对应getnumber[85])的每个bit位值
			for j=0,1 do
				for i=0,7 do
					local y = bit.band(getnumber((85-j)),bit.lshift(1,i))  --先低字节解析后高字节解析
					if(y == 0) then 
		               bitbuff_table[j*8+i+1] = 0
		            else
		               bitbuff_table[j*8+i+1] = 1
		            end 
				end
			end
			--将运行状态1的每位bit值转化为JSON格式数据
			for i=1,8,1 do
				packet[ status1_bit_cmds[i] ] = bitbuff_table[i]
			end
			for i=1,5,1 do
				packet[ status1_bit_cmds[8+i] ] = bitbuff_table[i+11]
			end

			--解析运行状态2(高字节对应getnumber[86],低字节对应getnumber[87])的每个bit位值
			for j=0,1 do
				for i=0,7 do
					local y = bit.band(getnumber((87-j)),bit.lshift(1,i)) --先低字节解析后高字节解析
					if(y == 0) then 
		               bitbuff_table[j*8+i+1] = 0
		            else
		               bitbuff_table[j*8+i+1] = 1
		            end 
				end
			end
			--将运行状态2的每位bit值转化为JSON格式数据
			packet[ status2_bit_cmds[1] ] = bitbuff_table[1]
			for i=1,7,1 do
				packet[ status2_bit_cmds[1+i] ] = bitbuff_table[i+4]
			end
			for i=1,2,1 do
				packet[ status2_bit_cmds[8+i] ] = bitbuff_table[i+14]
			end

			--解析运行状态3(高字节对应getnumber[88],低字节对应getnumber[89])的每个bit位值
			for j=0,1 do
				for i=0,7 do
					local y = bit.band(getnumber((89-j)),bit.lshift(1,i)) --先低字节解析后高字节解析
					if(y == 0) then 
		               bitbuff_table[j*8+i+1] = 0
		            else
		               bitbuff_table[j*8+i+1] = 1
		            end 
				end
			end
			--将运行状态3的每位bit值转化为JSON格式数据
			for i=1,16,1 do
				packet[ status3_bit_cmds[i] ] = bitbuff_table[i]
			end

			--解析运行状态4(高字节对应getnumber[90],低字节对应getnumber[91])的每个bit位值
			for j=0,1 do
				for i=0,7 do
					local y = bit.band(getnumber((91-j)),bit.lshift(1,i)) --先低字节解析后高字节解析
					if(y == 0) then 
		               bitbuff_table[j*8+i+1] = 0
		            else
		               bitbuff_table[j*8+i+1] = 1
		            end 
				end
			end
			--将运行状态4的每位bit值转化为JSON格式数据
			for i=1,12,1 do
				packet[ status4_bit_cmds[i] ] = bitbuff_table[i]
			end	
		
		end
	else 
		local head = string.sub(strload,3,6)
		if(head == 'IMSI') then
			packet['status'] = 'Heartbeat packet'
		else
			packet['head_error'] = 'error'
		end	
	end
	return Json(packet)
end

return _M
