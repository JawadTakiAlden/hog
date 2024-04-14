<?php

namespace App\Http\Controllers;

use App\Http\HelperFunction;
use App\HttpResponse\HTTPResponse;
use App\Models\ExportableFile;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;

class ExportableFileController extends Controller
{
    use HTTPResponse;
    public function getAllFiles()
    {
        $files = ExportableFile::all();
        return response()->json($files);
    }

    public function downloadFile($fileName)
    {
        $file = ExportableFile::where('path', $fileName)->first();
        if (!$file) {
            return $this->error('the requested file doesnt found in our system' , 404);
        }

        $filePath = 'excel_files/' . $fileName;
        return Storage::download($filePath);
    }

    public function deleteFile($fileName)
    {
        $file = ExportableFile::where('path', $fileName)->orderBy('created_at' , 'desc')->first();
        if (!$file) {
           return HelperFunction::notFoundResponce();
        }
        ExportableFile::where('path' , $fileName)->delete();
        $filePath = 'excel_files/' . $fileName;
        Storage::delete($filePath);
        return $this->success( null, __("messages.exportable_file_controller.delete" , ["file_name" => $fileName]));
    }
}
