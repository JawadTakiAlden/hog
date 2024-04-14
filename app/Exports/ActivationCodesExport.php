<?php

namespace App\Exports;

use App\Models\ActivationCode;
use Maatwebsite\Excel\Concerns\FromCollection;
use Maatwebsite\Excel\Concerns\WithHeadings;
use Maatwebsite\Excel\Concerns\WithStyles;
use PhpOffice\PhpSpreadsheet\Worksheet\Worksheet;

class ActivationCodesExport implements FromCollection, WithHeadings, WithStyles
{
    protected $activationCodes;

    public function __construct(array $activationCodes)
    {
        $this->activationCodes = collect($activationCodes);
    }

    public function collection()
    {
        return $this->activationCodes->map(function ($item) {
            return [
                'Code' => $item['code'],
                'Created At' => $item['created_at'],
            ];
        });
    }

    public function headings(): array
    {
        return [
            'Code',
            'Created At',
        ];
    }

    public function styles(Worksheet $sheet)
    {
        // Apply styles to the header row
        $sheet->getStyle('A1:D1')->applyFromArray([
            'font' => [
                'bold' => true,
                'color' => ['rgb' => 'FFFFFF'], // White font color
            ],
            'fill' => [
                'fillType' => \PhpOffice\PhpSpreadsheet\Style\Fill::FILL_SOLID,
                'startColor' => [
                    'rgb' => '000080', // Dark blue background color
                ],
            ],
        ]);
    }
}
