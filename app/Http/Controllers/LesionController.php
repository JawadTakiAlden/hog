<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\Http\Resources\LesionResource;
use App\HttpResponse\HTTPResponse;
use App\Models\Lesion;
use App\Http\Requests\StoreLesionRequest;
use App\Http\Requests\UpdateLesionRequest;
use App\Types\LesionType;
use Illuminate\Support\Facades\Storage;
use Vimeo\Vimeo;

class LesionController extends Controller
{
    use HTTPResponse;
    private Vimeo $client;

    public function __construct()
    {
        $this->client = new Vimeo("1a223f522e28ec1fb6b9e8e25f088348ecf1a6ef"
            , "xEjIb7Q0J2zYJRfsgpb1XRcwG2XRig/Nm5Gr3nejJMuFuuLGxr1lx0Z2A7kHN8MOvMPHhLG+pOX5fI5bk7WC5YIvQsPpv+9/pM2a8UlyqQOCfg7VqtGRZ9qtlHcOUH3t",
            "b666b813b6109e0574302a8d4237445a");
    }
    public function getAll($chpaterID){
        try {
            $chapter = HelperFunction::getChapterByID($chpaterID);
            if (!$chapter){
                return HelperFunction::notFoundResponce();
            }
            $lesions = Lesion::where('chapter_id' , $chpaterID)->get();
            return $this->success(LesionResource::collection($lesions));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function getVisible($chpaterID){
        try {
            $chapter = HelperFunction::getChapterByID($chpaterID);
            if (!$chapter){
                return HelperFunction::notFoundResponce();
            }
            $lesions = Lesion::where('chapter_id' , $chpaterID)->where('is_visible' , true)->get();
            return $this->success(LesionResource::collection($lesions));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function switchVisibility($lesionID){
        try {
            $lesion = HelperFunction::getLesionByID($lesionID);
            if (!$lesion){
                return HelperFunction::notFoundResponce();
            }
            $lesion->update([
               'is_visible' => !$lesion->is_visible
            ]);
            return $this->success( LesionResource::make($lesion) , __("messages.lesion_controller.visibility_switch"));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function delete($lesionID){
        try {
            $lesion = HelperFunction::getLesionByID($lesionID);
            if (!$lesion){
                return HelperFunction::notFoundResponce();
            }
            if ($lesion->type === 'pdf'){
                Storage::delete($lesion->link);
            }
            $lesion->delete();
            return $this->success(LesionResource::make($lesion) ,__("messages.lesion_controller.delete"));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function store(StoreLesionRequest $request){
        try {
            $type = $request->type;
            if ($type === 'pdf'){
                $pdfFile = $request->file('pdfFile');

                $pdfFile->store('pdf_lesions', 'public');
                $filePath = Storage::putFile('pdf_lesions', $pdfFile);
                $lesion = Lesion::create([
                    'title' => $request->title ?? $pdfFile->getClientOriginalName(),
                    'link' => $filePath,
                    'time' => $request->time ?? 0,
                    'is_open' => $request->is_open,
                    'is_visible' => $request->is_visible,
                    'type' => $type,
                    'chapter_id' => $request->chapter_id
                ]);

                return $this->success(  LesionResource::make($lesion),$lesion->title . __("messages.lesion_controller.create"));
            }else if ($type === 'video'){
                $response = $this->client->request($request->videoURI, array(), 'GET');
                $responseData = $response['body'];
                $date = [
                    'description' => $responseData['description'],
                    'link' => $responseData['uri'],
                    'time' => intval($responseData['duration']) / 60,
                    'is_open' => $request->is_open,
                    'is_visible' => $request->is_visible,
                    'type' => $type,
                    'chapter_id' => $request->chapter_id
                ];
                if ($request->title){
                    $date = array_merge($date , ['title' => $request->title]);
                }else{
                    $date = array_merge($date , ['title' => $responseData['name']]);
                }
                $lesion = Lesion::create($date);
                return $this->success(LesionResource::make($lesion) , __("messages.lesion_controller.create"));
            }else{
                return $this->error(__("messages.error.unknown_lesion_type") , 422);
            }
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function update(UpdateLesionRequest $request , $lesionID){
        try {
            $lesion = HelperFunction::getLesionByID($lesionID);
            if (!$lesion){
                return HelperFunction::notFoundResponce();
            }
            if ($lesion->type === LesionType::VIDEO){
                $data = [
                    'is_visible' => $request->is_visible,
                    'is_open' => $request->is_open,
                ];
                if ($request->videoURI){
                    $response = $this->client->request($request->videoURI, array(), 'GET');
                    $responseData = $response['body'];
                    $data = array_merge($data , [
                        'description' => $responseData['description'],
                        'time' => intval($responseData['duration']) / 60,
                        'link' => $responseData['uri'],
                    ]);
                    if (!$request->title){
                        $data['title'] = $responseData['name'];
                    }else{
                        $data['title'] = $request->title;
                    }
                }
                else{
                    $data['title'] = $request->title;
                }
                $lesion->update($data);
            }else {
                $data = [
                    'is_visible' => $request->is_visible,
                    'is_open' => $request->is_open,
                    'time' => $request->time,
                    'description' => $request->description
                ];

                if ($request->pdfFile){
                    Storage::delete($lesion->link);
                    $pdfFile = $request->file('pdfFile');
                    $pdfFile->store('pdf_lesions', 'public');
                    $filePath = Storage::putFile('pdf_lesions', $pdfFile);
                    $data['link'] = $filePath;
                    if (!$request->title){
                        $data['title'] = $pdfFile->getClientOriginalName();
                    }else{
                        $data['title'] = $request->title;
                    }
                }else{
                    $data['title'] = $request->title;
                }
                $lesion->update($data);
            }
            return $this->success(LesionResource::make($lesion) , __("messages.lesion_controller.update"));
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }

    public function getPdfLesion($path){
        try {
            $file = Storage::exists($path);
            if (!$file){
                return HelperFunction::notFoundResponce();
            }
            return Storage::get($path);
        }catch (\Throwable $th){
            return HelperFunction::ServerErrorResponse();
        }
    }
}
