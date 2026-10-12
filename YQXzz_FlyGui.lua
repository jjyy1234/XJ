local Players = game:GetService("Players")
local RunService = game:GetService("RunService")
local UserInputService = game:GetService("UserInputService")
local TweenService = game:GetService("TweenService")

local player = Players.LocalPlayer
local camera = workspace.CurrentCamera

local flySpeed = 50
local MIN_SPEED, MAX_SPEED = 1, 1000
local flying = false
local flyConnection
local bodyVelocity, bodyGyro

local function getUIScale()
	local cam = workspace.CurrentCamera
	local vp = cam and cam.ViewportSize or Vector2.new(800, 600)
	local short = math.min(vp.X, vp.Y)
	return math.clamp(short / 500, 0.75, 1.35)
end

local S = getUIScale()
local function px(n)
	return math.floor(n * S + 0.5)
end

local screenGui = Instance.new("ScreenGui")
screenGui.Name = "YQXzzFlyUI"
screenGui.ResetOnSpawn = false
screenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
screenGui.IgnoreGuiInset = true
screenGui.Parent = player:WaitForChild("PlayerGui")

local FRAME_W = px(240)
local FRAME_H = px(145)

local mainFrame = Instance.new("Frame")
mainFrame.Name = "Main"
mainFrame.Size = UDim2.new(0, FRAME_W, 0, FRAME_H)
mainFrame.Position = UDim2.new(0.5, -FRAME_W/2, 0.38, 0)
mainFrame.BackgroundColor3 = Color3.fromRGB(250, 238, 245)
mainFrame.BackgroundTransparency = 0.04
mainFrame.BorderSizePixel = 0
mainFrame.ClipsDescendants = true
mainFrame.Parent = screenGui
mainFrame.Active = true

local frameCorner = Instance.new("UICorner")
frameCorner.CornerRadius = UDim.new(0, px(14))
frameCorner.Parent = mainFrame

local frameStroke = Instance.new("UIStroke")
frameStroke.Parent = mainFrame
frameStroke.Color = Color3.fromRGB(225, 198, 215)
frameStroke.Thickness = math.max(1, S * 1.2)
frameStroke.Transparency = 0.15

local titleBar = Instance.new("Frame")
titleBar.Name = "TitleBar"
titleBar.Size = UDim2.new(1, 0, 0, px(32))
titleBar.BackgroundTransparency = 1
titleBar.Parent = mainFrame
titleBar.Active = true

local title = Instance.new("TextLabel")
title.Size = UDim2.new(0, px(120), 1, 0)
title.Position = UDim2.new(0, px(12), 0, 0)
title.BackgroundTransparency = 1
title.Text = "YQXzz"
title.TextColor3 = Color3.fromRGB(145, 140, 155)
title.Font = Enum.Font.SourceSansItalic
title.TextSize = px(24)
title.TextXAlignment = Enum.TextXAlignment.Left
title.Parent = titleBar

local subTitle = Instance.new("TextLabel")
subTitle.Size = UDim2.new(0, px(110), 0, px(14))
subTitle.Position = UDim2.new(0, px(13), 0, px(26))
subTitle.BackgroundTransparency = 1
subTitle.Text = "FLY  •  CONTROL"
subTitle.TextColor3 = Color3.fromRGB(173, 144, 163)
subTitle.Font = Enum.Font.GothamMedium
subTitle.TextSize = px(9)
subTitle.TextXAlignment = Enum.TextXAlignment.Left
subTitle.Parent = mainFrame

local closeBtn = Instance.new("TextButton")
closeBtn.Name = "Close"
closeBtn.Size = UDim2.new(0, px(24), 0, px(24))
closeBtn.Position = UDim2.new(1, -px(30), 0, px(6))
closeBtn.BackgroundColor3 = Color3.fromRGB(245, 179, 188)
closeBtn.BorderSizePixel = 0
closeBtn.Text = "×"
closeBtn.TextColor3 = Color3.fromRGB(125, 75, 85)
closeBtn.Font = Enum.Font.GothamBold
closeBtn.TextSize = px(14)
closeBtn.AutoButtonColor = false
closeBtn.Parent = mainFrame
Instance.new("UICorner", closeBtn).CornerRadius = UDim.new(1, 0)

local minBtn = Instance.new("TextButton")
minBtn.Name = "Minimize"
minBtn.Size = UDim2.new(0, px(24), 0, px(24))
minBtn.Position = UDim2.new(1, -px(58), 0, px(6))
minBtn.BackgroundColor3 = Color3.fromRGB(215, 202, 232)
minBtn.BorderSizePixel = 0
minBtn.Text = "−"
minBtn.TextColor3 = Color3.fromRGB(110, 91, 130)
minBtn.Font = Enum.Font.GothamBold
minBtn.TextSize = px(15)
minBtn.AutoButtonColor = false
minBtn.Parent = mainFrame
Instance.new("UICorner", minBtn).CornerRadius = UDim.new(1, 0)

local content = Instance.new("Frame")
content.Name = "Content"
content.Size = UDim2.new(1, 0, 1, -px(42))
content.Position = UDim2.new(0, 0, 0, px(42))
content.BackgroundTransparency = 1
content.Parent = mainFrame

local speedLabel = Instance.new("TextLabel")
speedLabel.Size = UDim2.new(0, px(80), 0, px(28))
speedLabel.Position = UDim2.new(0, px(14), 0, px(8))
speedLabel.BackgroundTransparency = 1
speedLabel.Text = "Fly Speed:"
speedLabel.TextColor3 = Color3.fromRGB(145, 103, 134)
speedLabel.Font = Enum.Font.GothamMedium
speedLabel.TextSize = px(13)
speedLabel.TextXAlignment = Enum.TextXAlignment.Left
speedLabel.Parent = content

local speedBox = Instance.new("TextBox")
speedBox.Name = "SpeedBox"
speedBox.Size = UDim2.new(0, px(110), 0, px(28))
speedBox.Position = UDim2.new(0, px(100), 0, px(8))
speedBox.BackgroundColor3 = Color3.fromRGB(255, 224, 190)
speedBox.BorderSizePixel = 0
speedBox.Text = tostring(flySpeed)
speedBox.PlaceholderText = "Type speed"
speedBox.TextColor3 = Color3.fromRGB(147, 105, 75)
speedBox.Font = Enum.Font.GothamBold
speedBox.TextSize = px(13)
speedBox.ClearTextOnFocus = false
speedBox.Parent = content
Instance.new("UICorner", speedBox).CornerRadius = UDim.new(0, px(8))

local flyBtn = Instance.new("TextButton")
flyBtn.Name = "FlyToggle"
flyBtn.Size = UDim2.new(1, -px(28), 0, px(36))
flyBtn.Position = UDim2.new(0, px(14), 0, px(48))
flyBtn.BackgroundColor3 = Color3.fromRGB(191, 226, 205)
flyBtn.BorderSizePixel = 0
flyBtn.Text = "FLY: OFF"
flyBtn.TextColor3 = Color3.fromRGB(72, 108, 88)
flyBtn.Font = Enum.Font.GothamBold
flyBtn.TextSize = px(14)
flyBtn.AutoButtonColor = false
flyBtn.Parent = content
Instance.new("UICorner", flyBtn).CornerRadius = UDim.new(0, px(10))

local mini2 = Instance.new("TextButton")
mini2.Name = "minimize2"
mini2.Position = mainFrame.Position
mini2.Size = UDim2.new(0, px(52), 0, px(34))
mini2.BackgroundColor3 = Color3.fromRGB(250, 238, 245)
mini2.BorderSizePixel = 0
mini2.Text = "Y"
mini2.TextColor3 = Color3.fromRGB(145, 140, 155)
mini2.Font = Enum.Font.SourceSansItalic
mini2.TextSize = px(20)
mini2.Visible = false
mini2.Parent = screenGui
Instance.new("UICorner", mini2).CornerRadius = UDim.new(0, px(12))

local function getCharacterParts()
	local char = player.Character
	if not char then return end
	local root = char:FindFirstChild("HumanoidRootPart")
	local hum = char:FindFirstChildOfClass("Humanoid")
	return char, root, hum
end

local function stopFly()
	flying = false
	if flyConnection then
		flyConnection:Disconnect()
		flyConnection = nil
	end
	if bodyVelocity then bodyVelocity:Destroy() bodyVelocity = nil end
	if bodyGyro then bodyGyro:Destroy() bodyGyro = nil end

	local _, _, hum = getCharacterParts()
	if hum then hum.PlatformStand = false end

	flyBtn.Text = "FLY: OFF"
	flyBtn.BackgroundColor3 = Color3.fromRGB(191, 226, 205)
	flyBtn.TextColor3 = Color3.fromRGB(72, 108, 88)
end

local function startFly()
	local _, root, hum = getCharacterParts()
	if not root or not hum then return end

	flying = true
	hum.PlatformStand = true

	bodyVelocity = Instance.new("BodyVelocity")
	bodyVelocity.MaxForce = Vector3.new(1e9, 1e9, 1e9)
	bodyVelocity.Velocity = Vector3.zero
	bodyVelocity.Parent = root

	bodyGyro = Instance.new("BodyGyro")
	bodyGyro.MaxTorque = Vector3.new(1e9, 1e9, 1e9)
	bodyGyro.P = 9e4
	bodyGyro.CFrame = camera.CFrame
	bodyGyro.Parent = root

	flyBtn.Text = "FLY: ON"
	flyBtn.BackgroundColor3 = Color3.fromRGB(170, 220, 191)
	flyBtn.TextColor3 = Color3.fromRGB(55, 95, 70)

	flyConnection = RunService.RenderStepped:Connect(function()
		local _, r, h = getCharacterParts()
		if not r or not h or not bodyVelocity then
			stopFly()
			return
		end

		camera = workspace.CurrentCamera
		local camCF = camera.CFrame
		local direction = Vector3.zero

		local moveDir = h.MoveDirection
		if moveDir.Magnitude > 0 then
			local flatLook = Vector3.new(camCF.LookVector.X, 0, camCF.LookVector.Z)
			local flatRight = Vector3.new(camCF.RightVector.X, 0, camCF.RightVector.Z)
			if flatLook.Magnitude > 0.001 then flatLook = flatLook.Unit end
			if flatRight.Magnitude > 0.001 then flatRight = flatRight.Unit end
			local forwardAmt = moveDir:Dot(flatLook)
			local rightAmt = moveDir:Dot(flatRight)
			direction = camCF.LookVector * forwardAmt + camCF.RightVector * rightAmt
		end

		if not UserInputService:GetFocusedTextBox() then
			if UserInputService:IsKeyDown(Enum.KeyCode.Space) then
				direction += Vector3.new(0, 1, 0)
			end
			if UserInputService:IsKeyDown(Enum.KeyCode.LeftControl)
				or UserInputService:IsKeyDown(Enum.KeyCode.LeftShift) then
				direction -= Vector3.new(0, 1, 0)
			end
		end

		if direction.Magnitude > 0 then
			direction = direction.Unit
		end

		bodyVelocity.Velocity = direction * flySpeed
		bodyGyro.CFrame = camCF
	end)
end

local function toggleFly()
	if flying then
		stopFly()
	else
		startFly()
	end
end

flyBtn.MouseButton1Click:Connect(toggleFly)

speedBox.FocusLost:Connect(function()
	local value = tonumber(speedBox.Text)
	if value then
		flySpeed = math.clamp(value, MIN_SPEED, MAX_SPEED)
	end
	speedBox.Text = tostring(flySpeed)
end)

local minimized = false
minBtn.MouseButton1Click:Connect(function()
	minimized = not minimized
	content.Visible = not minimized
	subTitle.Visible = not minimized
	mainFrame.Size = minimized and UDim2.new(0, FRAME_W, 0, px(32)) or UDim2.new(0, FRAME_W, 0, FRAME_H)
	minBtn.Text = minimized and "+" or "−"
end)

closeBtn.MouseButton1Click:Connect(function()
	stopFly()
	screenGui:Destroy()
end)

mini2.MouseButton1Click:Connect(function()
	mini2.Visible = false
	mainFrame.Visible = true
end)

player.CharacterAdded:Connect(function()
	if flying then stopFly() end
end)

local dragging = false
local dragStart = nil
local startPos = nil

local function startDrag(input)
	if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
		dragging = true
		dragStart = input.Position
		startPos = mainFrame.Position
	end
end

local function updateDrag(input)
	if dragging and dragStart and startPos then
		local delta = input.Position - dragStart
		mainFrame.Position = UDim2.new(
			startPos.X.Scale,
			startPos.X.Offset + delta.X,
			startPos.Y.Scale,
			startPos.Y.Offset + delta.Y
		)
	end
end

local function endDrag(input)
	if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
		dragging = false
		dragStart = nil
		startPos = nil
	end
end

titleBar.InputBegan:Connect(startDrag)
mainFrame.InputBegan:Connect(startDrag)

UserInputService.InputChanged:Connect(function(input)
	if dragging and (input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch) then
		updateDrag(input)
	end
end)

UserInputService.InputEnded:Connect(endDrag)

local function addEffect(button, normal)
	button.MouseEnter:Connect(function()
		TweenService:Create(button, TweenInfo.new(0.12), {
			BackgroundColor3 = normal:Lerp(Color3.new(1,1,1), 0.12)
		}):Play()
	end)
	button.MouseLeave:Connect(function()
		TweenService:Create(button, TweenInfo.new(0.12), {
			BackgroundColor3 = normal
		}):Play()
	end)
end

addEffect(flyBtn, Color3.fromRGB(191, 226, 205))
addEffect(closeBtn, Color3.fromRGB(245, 179, 188))
addEffect(minBtn, Color3.fromRGB(215, 202, 232))