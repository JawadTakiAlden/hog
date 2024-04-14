<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Relations\Pivot;

class ChapterQuiz extends Pivot
{
    protected $guarded = ['id'];
}
