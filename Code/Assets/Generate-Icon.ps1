#
# Copyright (c) Bryan Berns.
# Licensed under GPLv3. See LICENSE.md.
#

# Load the WPF drawing types and stop if icon generation fails.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName PresentationCore, WindowsBase

# Define the certificate-and-shield artwork in a common 64-pixel coordinate space.
$shapes = @(
    @('M12 5H39L50 16V53H12Z', '#EAF1F7', '#19384F', 3),
    @('M39 5V16H50', $null, '#19384F', 3),
    @('M21 23H40M21 31H34M21 39H29', $null, '#19384F', 3),
    @('M43 29L59 35V44C59 52 52 58 43 61C34 58 27 52 27 44V35Z', '#168A91', '#19384F', 3),
    @('M35 44L41 50L52 39', $null, '#FFFFFF', 4)
)

# Render a transparent frame for each Windows icon size.
$frames = foreach ($size in @(16, 24, 32, 48, 64, 128, 256))
{
    $visual = [System.Windows.Media.DrawingVisual]::new()
    $drawing = $visual.RenderOpen()
    $drawing.PushTransform([System.Windows.Media.ScaleTransform]::new($size / 64.0, $size / 64.0))
    foreach ($shape in $shapes)
    {
        # Draw each shape with its configured fill and rounded stroke.
        $fill = if ($shape[1]) { [System.Windows.Media.BrushConverter]::new().ConvertFromString($shape[1]) } else { $null }
        $stroke = [System.Windows.Media.BrushConverter]::new().ConvertFromString($shape[2])
        $pen = [System.Windows.Media.Pen]::new($stroke, $shape[3])
        $pen.StartLineCap = $pen.EndLineCap = [System.Windows.Media.PenLineCap]::Round
        $pen.LineJoin = [System.Windows.Media.PenLineJoin]::Round
        $drawing.DrawGeometry($fill, $pen, [System.Windows.Media.Geometry]::Parse($shape[0]))
    }
    # Rasterize the scaled artwork and encode the frame as PNG bytes.
    $drawing.Pop()
    $drawing.Close()
    $bitmap = [System.Windows.Media.Imaging.RenderTargetBitmap]::new($size, $size, 96, 96,
        [System.Windows.Media.PixelFormats]::Pbgra32)
    $bitmap.Render($visual)
    $encoder = [System.Windows.Media.Imaging.PngBitmapEncoder]::new()
    $encoder.Frames.Add([System.Windows.Media.Imaging.BitmapFrame]::Create($bitmap))
    $stream = [System.IO.MemoryStream]::new()
    try
    {
        $encoder.Save($stream)
        [pscustomobject]@{ Size = $size; Bytes = $stream.ToArray() }
    }
    finally { $stream.Dispose() }
}
# Open the icon container that will hold the generated image frames.
$file = [System.IO.File]::Create((Join-Path $PSScriptRoot 'Certitude.ico'))
$writer = [System.IO.BinaryWriter]::new($file)
try
{
    # Write the ICO header and calculate the first frame payload offset.
    $writer.Write([uint16]0)
    $writer.Write([uint16]1)
    $writer.Write([uint16]$frames.Count)
    $offset = 6 + 16 * $frames.Count
    foreach ($frame in $frames)
    {
        # Write each frame directory entry, using zero for the 256-pixel dimension.
        $dimension = if ($frame.Size -eq 256) { 0 } else { $frame.Size }
        $writer.Write([byte]$dimension); $writer.Write([byte]$dimension)
        $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]32)
        $writer.Write([uint32]$frame.Bytes.Length); $writer.Write([uint32]$offset)
        $offset += $frame.Bytes.Length
    }
    # Append the PNG payloads after all frame directory entries.
    foreach ($frame in $frames) { $writer.Write([byte[]]$frame.Bytes) }
}
finally { $writer.Dispose() }

# Save the largest frame separately for the application title artwork.
[System.IO.File]::WriteAllBytes((Join-Path $PSScriptRoot 'Certitude.png'), $frames[-1].Bytes)
