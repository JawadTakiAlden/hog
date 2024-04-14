<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Requests\UpdateNewsRequest;
use App\Http\Resources\NewsResource;
use App\HttpResponse\HTTPResponse;
use App\Models\News;
use App\Http\Requests\StoreNewsRequest;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\File;

class NewsController extends Controller
{
    use HTTPResponse;
    public function index()
    {
        try {
            $news = News::orderBy('position_update' , 'desc')->orderBy('position')->get();
            return $this->success(NewsResource::collection($news));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function visibleNews(){
        try {
            $news = News::where('is_visible' , true)->orderBy('position_update', 'desc')->orderBy('position')->get();
            return $this->success(NewsResource::collection($news));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
    public function store(StoreNewsRequest $request)
    {
        try {
            $news = News::create($request->only(['is_visible' , 'image' , 'position' , 'title']));
            return $this->success(NewsResource::make($news) , __("messages.news_controller.create"));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function update(UpdateNewsRequest $request , $newsID){
        {
            try {
                $news = HelperFunction::getNewsByID($newsID);
                if (!$news){
                    return HelperFunction::notFoundResponce();
                }
                if ($request->position){
                    if (intval($request->position) !== intval($news->position)){
                        $news->update(array_merge($request->only(['title' , 'position' , 'is_visible' , 'image']) , ['position_update' => DB::raw('CURRENT_TIMESTAMP')]));
                        return $this->success(NewsResource::make($news) , __("messages.news_controller.update"));
                    }else{
                        $news->update($request->only(['title' , 'is_visible' , 'image']));
                        return $this->success(NewsResource::make($news) , __("messages.news_controller.update"));
                    }
                }
                $news->update($request->only(['title' , 'is_visible' , 'image']));
                return $this->success(NewsResource::make($news) , __("messages.news_controller.update"));
            }catch(\Throwable $th){
                return HelperFunction::ServerErrorResponse();
            }
        }
    }

    public function destroy($newsID)
    {
        try {
            $news = HelperFunction::getNewsByID($newsID);
            if (!$news){
                return HelperFunction::notFoundResponce();
            }
            if (File::exists(public_path($news->image))) {
                File::delete(public_path($news->image));
            }
            $news->delete();
            return $this->success(NewsResource::make($news) ,__("messages.news_controller.delete"));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function show($newsID){
        try {
            $news = HelperFunction::getNewsByID($newsID);
            if (!$news){
                return HelperFunction::notFoundResponce();
            }
            return $this->success(NewsResource::make($news));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function switchVisibility($newsID){
        try {
            $news = HelperFunction::getNewsByID($newsID);
            if (!$news){
                return HelperFunction::notFoundResponce();
            }
            $news->update([
                'is_visible' => !$news->is_visible
            ]);
            return $this->success(NewsResource::make($news) , __("messages.news_controller.visibility_switch"));
        }catch(\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
}
