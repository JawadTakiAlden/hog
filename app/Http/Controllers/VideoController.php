<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Resources\VideoResource;
use App\HttpResponse\HTTPResponse;
use Illuminate\Http\Request;
use Vimeo\Vimeo;

class VideoController extends Controller
{
    use HTTPResponse;

    private Vimeo $client;

    public function __construct()
    {
        $this->client = new Vimeo("1a223f522e28ec1fb6b9e8e25f088348ecf1a6ef"
            , "xEjIb7Q0J2zYJRfsgpb1XRcwG2XRig/Nm5Gr3nejJMuFuuLGxr1lx0Z2A7kHN8MOvMPHhLG+pOX5fI5bk7WC5YIvQsPpv+9/pM2a8UlyqQOCfg7VqtGRZ9qtlHcOUH3t",
            "b666b813b6109e0574302a8d4237445a");
    }

    public function getVideos () {
        try {
            $queryParams = [];
            if (\request('link')) {
                $link = \request('link');
                $link = strtok($link, '?');
                $queryParams['query'] = $link;
            }
            $response = $this->client->request('/users/216130188/videos',$queryParams, 'GET');
            $responseData = $response['body'];
            $videos = $responseData['data'];
            $test = collect($videos);
            return $this->success(VideoResource::collection($test));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function watch(){
        try {
            if (!\request('link')){
                return $this->error(__('messages.video_controller.link_not_correct') , 500);
            }
            $video = $this->client->request(\request('link').'?fields=play');
            $data = $video['body'];
            $data = $data['play'];
            $data = $data['progressive'];
            return response([
                'link' => $data
            ] , 200);
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function download(){
        try {
            if (!\request('link')){
                return $this->error(__('messages.video_controller.link_not_correct') , 500);
            }
            $video = $this->client->request(\request('link').'?fields=download');
            $downloadArray = $video['body'];
            return response([
                'link' => $downloadArray
            ] , 200);
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
}
