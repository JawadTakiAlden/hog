<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ $data['name'] }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 800px;
            margin: 0 auto;
            background-color: #fff;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        h2 {
            text-align: center;
            color: #333;
        }
        .video-container {
            position: relative;
            width: 100%;
            padding-top: 56.25%; /* 16:9 aspect ratio */
            overflow: hidden;
        }
        .video-container iframe {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            border: none;
        }
        .button-container{
            width: 100%;
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        #downloadButton{
            color: #fff;
            background-color: dodgerblue;
            padding: 10px 25px;
            margin: 10px auto;
            width: fit-content;
            border-radius: 12px;
            border: none;
            outline: none;
            text-align: center;
            cursor: pointer;
            text-transform: capitalize;
            transition: 0.3s;
        }
        #downloadButton:hover{
            background-color: blueviolet;
        }
    </style>
</head>
<body>
<div class="container">
    <h2>{{ $data['name'] }}</h2>
    <div class="video-container">
        <iframe src="{{ $data['player_embed_url'] }}" allowfullscreen></iframe>
    </div>
</div>

<script src="{{$data['player_embed_url']}}"></script>
<script>
    var iframe = document.querySelector('iframe');
    var player = new Vimeo.Player(iframe);

    player.on('play', function() {
        console.log('Played the video');
    });

    player.getVideoTitle().then(function(title) {
        console.log('title:', title);
    });
</script>
</body>
</html>
